// SPDX-License-Identifier: MIT
//! The in-app panel's controller against a fake engine: state machine, bounded
//! fetches, dropping of requests made for a stop that is over, the shared
//! breakpoint table, and one-controller-at-a-time against a real RSP client.
use crate::debug::{
    ArchTag, DebugBackend, DebugCaps, DebugError, DebugServer, DetachMode, RegsetBlob, RegsetInfo,
    ResumeAction, StopEvent, StopKind, TargetState, ThreadInfo,
    amd64::{FXSAVE_SIZE, NT_PRFPREG, NT_PRSTATUS, USER_REGS_SIZE},
    debugger::Debugger,
    ui_control::{PanelControl, PanelHandle, Pump},
    view::{
        BreakpointKind, Controller, DebugAction, DebugRequest, DebugView, Pending, RunState,
        StopReason, WatchAccess, WindowKind,
    },
};
use std::{
    net::TcpStream,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const CODE: u64 = 0x40_1000;
const STACK: u64 = 0x7ffd_0000;
const TID: u32 = 77;
/// Where the fake process stops: far enough into the code for context before it.
const PC: u64 = CODE + 0x60;

struct Engine {
    state: TargetState,
    sequence: u32,
    pc: u64,
    memory_code: Vec<u8>,
    breakpoints: Vec<u64>,
    /// Every guest request, by name.
    calls: Vec<String>,
}
impl Engine {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            state: TargetState::Running,
            sequence: 0,
            pc: PC,
            // nop x4, push rbp, mov rbp,rsp, sub rsp,0x10, then nops
            memory_code: [
                vec![0x90; 4],
                vec![0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10],
                vec![0x90; 0x200],
            ]
            .concat(),
            breakpoints: Vec::new(),
            calls: Vec::new(),
        }))
    }
    fn stop(&mut self, kind: StopKind) {
        self.sequence += 1;
        self.state = TargetState::Stopped(StopEvent {
            sequence: self.sequence,
            kind,
            tid: TID,
            pc: self.pc,
        });
    }
}

struct Fake(Arc<Mutex<Engine>>, DebugCaps);
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
        max_threads: 16,
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
impl DebugBackend for Fake {
    fn caps(&self) -> &DebugCaps {
        &self.1
    }
    fn state(&mut self) -> Result<TargetState, DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push("state".into());
        Ok(engine.state)
    }
    fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push("threads".into());
        Ok(vec![
            ThreadInfo {
                tid: TID,
                stopped: true,
                pc: engine.pc,
                signal: 0,
                vfork_wait: false,
            },
            ThreadInfo {
                tid: TID + 1,
                stopped: true,
                pc: 0x40_1100,
                signal: 0,
                vfork_wait: false,
            },
        ])
    }
    fn interrupt(&mut self) -> Result<(), DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push("interrupt".into());
        if engine.state == TargetState::Running {
            engine.stop(StopKind::Interrupt);
        }
        Ok(())
    }
    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("{action:?}"));
        match action {
            ResumeAction::Continue | ResumeAction::ContinueSignal { .. } => {
                engine.state = TargetState::Running
            }
            ResumeAction::Step { .. } | ResumeAction::StepSignal { .. } => {
                engine.pc += 1;
                engine.stop(StopKind::Step);
            }
        }
        Ok(())
    }
    fn read_regset(&mut self, tid: u32, nt_type: u32) -> Result<RegsetBlob, DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("regs {tid} {nt_type}"));
        let data = match nt_type {
            NT_PRSTATUS => {
                let mut blob = vec![0u8; USER_REGS_SIZE];
                let pc = if tid == TID { engine.pc } else { 0x40_1100 };
                blob[128..136].copy_from_slice(&pc.to_le_bytes()); // rip
                blob[152..160].copy_from_slice(&STACK.to_le_bytes()); // rsp
                blob[144..152].copy_from_slice(&0x246u64.to_le_bytes()); // eflags
                blob[168..176].copy_from_slice(&0x7fff_1234_0000u64.to_le_bytes()); // fs_base
                blob
            }
            _ => vec![0u8; FXSAVE_SIZE],
        };
        Ok(RegsetBlob { nt_type, data })
    }
    fn write_regset(&mut self, _tid: u32, _blob: &RegsetBlob) -> Result<(), DebugError> {
        Ok(())
    }
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("mem {addr:#x} {len}"));
        if (CODE..CODE + engine.memory_code.len() as u64).contains(&addr) {
            let start = (addr - CODE) as usize;
            let end = (start + len).min(engine.memory_code.len());
            return Ok(engine.memory_code[start..end].to_vec());
        }
        if (STACK..STACK + 0x1000).contains(&addr) {
            let count = len.min((STACK + 0x1000 - addr) as usize);
            return Ok((0..count).map(|index| index as u8).collect());
        }
        Err(DebugError::Fault)
    }
    fn write_memory(&mut self, _addr: u64, _data: &[u8]) -> Result<(), DebugError> {
        Ok(())
    }
    fn set_breakpoint(&mut self, addr: u64, _len: u32) -> Result<(), DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("set {addr:#x}"));
        if addr >= STACK {
            return Err(DebugError::Fault);
        }
        engine.breakpoints.push(addr);
        Ok(())
    }
    fn clear_breakpoint(&mut self, addr: u64, _len: u32) -> Result<(), DebugError> {
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("clear {addr:#x}"));
        engine.breakpoints.retain(|existing| *existing != addr);
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
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("hw+ {kind:?} {addr:#x} {len}"));
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
        let mut engine = self.0.lock().unwrap();
        engine.calls.push(format!("hw- {kind:?} {addr:#x} {len}"));
        Ok(())
    }
    fn detach(&mut self, mode: DetachMode) -> Result<(), DebugError> {
        self.0
            .lock()
            .unwrap()
            .calls
            .push(format!("detach {mode:?}"));
        Ok(())
    }
}

struct Rig {
    engine: Arc<Mutex<Engine>>,
    target: Debugger,
    control: PanelControl,
    handle: PanelHandle,
    next: u64,
}
impl Rig {
    fn new() -> Self {
        Self::with_caps(caps())
    }
    /// A guest with the debug registers (Phase 2).
    fn hardware() -> Self {
        Self::with_caps(DebugCaps {
            hardware_breakpoints: 4,
            hardware_watchpoints: 4,
            watch_len_mask: 0x8b,
            ..caps()
        })
    }
    fn with_caps(caps: DebugCaps) -> Self {
        let engine = Engine::new();
        let fake = Fake(engine.clone(), caps);
        let (mut control, handle) = PanelControl::new(fake.caps());
        control.timing(Duration::ZERO, Duration::ZERO, Duration::from_secs(5));
        Self {
            engine,
            target: Debugger::new(Box::new(fake)),
            control,
            handle,
            next: 1,
        }
    }
    fn view(&self) -> Arc<DebugView> {
        self.handle.view()
    }
    fn send(&mut self, action: DebugAction) -> u64 {
        let sequence = self.view().run.stopped_sequence().unwrap_or(0);
        self.send_for(sequence, action)
    }
    fn send_for(&mut self, sequence: u32, action: DebugAction) -> u64 {
        let id = self.next;
        self.next += 1;
        self.handle
            .submit(DebugRequest {
                id,
                sequence,
                action,
            })
            .unwrap();
        id
    }
    fn pump(&mut self) -> Pump {
        self.control.pump(&mut self.target)
    }
    fn pump_until(&mut self, done: impl Fn(&DebugView) -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while !done(&self.view()) {
            assert!(
                Instant::now() < until,
                "view never settled: {:?}",
                self.view()
            );
            assert_eq!(self.pump(), Pump::Idle);
        }
    }
    fn calls(&self) -> Vec<String> {
        self.engine.lock().unwrap().calls.clone()
    }
    fn count(&self, prefix: &str) -> usize {
        self.calls()
            .iter()
            .filter(|call| call.starts_with(prefix))
            .count()
    }
    /// Stop the (initially running) process and wait for its data.
    fn stopped(&mut self) {
        self.pump();
        self.send(DebugAction::Stop);
        self.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
    }
}

#[test]
fn attach_reads_the_state_and_a_stop_fetches_a_bounded_set_once() {
    let mut rig = Rig::new();
    rig.pump();
    let view = rig.view();
    assert_eq!(
        view.run,
        RunState::Running {
            pending: Pending::Nothing
        }
    );
    assert_eq!(
        rig.count("mem"),
        0,
        "nothing is read while the process runs"
    );

    rig.send(DebugAction::Stop);
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
    let view = rig.view();
    assert!(matches!(
        view.run,
        RunState::Stopped { reason: StopReason::Interrupt, tid: TID, pc, sequence: 1 } if pc == PC
    ));
    assert_eq!(view.selected_tid, Some(TID));
    assert_eq!(view.threads.len(), 2);
    let registers = view.registers.as_ref().unwrap();
    assert_eq!(registers.get("rip"), Some(PC));
    assert_eq!(registers.get("rsp"), Some(STACK));
    assert_eq!(registers.get("fs_base"), Some(0x7fff_1234_0000));
    assert_eq!(registers.get("eflags"), Some(0x246));
    let code = view.window(WindowKind::Code).unwrap();
    assert_eq!(code.address, PC - 48, "48 bytes of context before rip");
    assert_eq!(code.bytes.len(), 48 + 208, "bounded around rip");
    let stack = view.window(WindowKind::Stack).unwrap();
    assert_eq!((stack.address, stack.bytes.len()), (STACK, 256));
    // One regset (not the floating-point one), one code window, one stack window.
    assert_eq!(rig.count("regs"), 1);
    assert_eq!(rig.count("threads"), 1);
    assert_eq!(rig.count("mem"), 2);
    // No traffic when idle at a stop.
    let before = rig.calls().len();
    for _ in 0..5 {
        rig.pump();
    }
    assert_eq!(rig.calls().len(), before);
}

#[test]
fn a_step_moves_one_instruction_and_a_stale_request_is_dropped() {
    let mut rig = Rig::new();
    rig.stopped();
    let first = rig.view().run.stopped_sequence().unwrap();
    let stale = first;
    rig.send(DebugAction::Step { tid: TID });
    rig.pump_until(|view| view.run.stopped_sequence().is_some_and(|s| s > first) && !view.loading);
    let view = rig.view();
    assert!(matches!(
        view.run,
        RunState::Stopped { reason: StopReason::Step, pc, .. } if pc == PC + 1
    ));
    assert_eq!(view.registers.as_ref().unwrap().get("rip"), Some(PC + 1));
    assert_eq!(rig.count("Step"), 1);

    // A second step made for the first stop must not run.
    let id = rig.send_for(stale, DebugAction::Step { tid: TID });
    rig.pump();
    let view = rig.view();
    assert!(view.handled >= id, "the request is answered");
    assert!(view.notice.as_deref().unwrap().contains("Dropped"));
    assert_eq!(
        rig.count("Step"),
        1,
        "the stale step never reached the guest"
    );
    assert_eq!(view.run.stopped_sequence(), Some(first + 1));
}

#[test]
fn continue_runs_until_a_breakpoint_and_clears_the_old_stop() {
    let mut rig = Rig::new();
    rig.stopped();
    rig.send(DebugAction::AddBreakpoint {
        addr: CODE + 8,
        kind: BreakpointKind::Software,
    });
    rig.pump();
    assert_eq!(rig.view().breakpoints.len(), 1);
    assert_eq!(rig.engine.lock().unwrap().breakpoints, [CODE + 8]);

    rig.send(DebugAction::Continue);
    rig.pump();
    let view = rig.view();
    assert_eq!(
        view.run,
        RunState::Running {
            pending: Pending::Nothing
        }
    );
    assert!(view.registers.is_none() && view.code.is_none() && view.threads.is_empty());

    // The guest reports the breakpoint hit.
    {
        let mut engine = rig.engine.lock().unwrap();
        engine.pc = CODE + 8;
        engine.stop(StopKind::Breakpoint { addr: CODE + 8 });
    }
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
    let view = rig.view();
    assert!(matches!(
        view.run,
        RunState::Stopped {
            reason: StopReason::Breakpoint { addr, kind: BreakpointKind::Software },
            ..
        } if addr == CODE + 8
    ));
    assert_eq!(view.registers.as_ref().unwrap().get("rip"), Some(CODE + 8));
}

#[test]
fn breakpoints_change_only_while_stopped_and_refused_ones_are_not_kept() {
    let mut rig = Rig::new();
    rig.pump();
    rig.send(DebugAction::AddBreakpoint {
        addr: CODE,
        kind: BreakpointKind::Software,
    });
    rig.pump();
    assert!(rig.view().breakpoints.is_empty());
    assert!(
        rig.view()
            .notice
            .as_deref()
            .unwrap()
            .contains("Stop the process")
    );
    assert_eq!(rig.count("set"), 0);

    rig.stopped();
    // The guest refuses an unwritable address: it is reported and not listed.
    rig.send(DebugAction::AddBreakpoint {
        addr: STACK + 8,
        kind: BreakpointKind::Software,
    });
    rig.pump();
    assert!(rig.view().breakpoints.is_empty());
    assert!(rig.view().notice.as_deref().unwrap().contains("cannot set"));

    // A duplicate is refused without asking the guest again.
    for _ in 0..2 {
        rig.send(DebugAction::AddBreakpoint {
            addr: CODE + 16,
            kind: BreakpointKind::Software,
        });
        rig.pump();
    }
    assert_eq!(rig.count("set 0x401010"), 1);
    assert!(rig.view().notice.as_deref().unwrap().contains("already"));

    // Disable removes it from the guest but keeps it listed; enable restores it.
    rig.send(DebugAction::SetBreakpointEnabled {
        addr: CODE + 16,
        enabled: false,
    });
    rig.pump();
    assert!(!rig.view().breakpoints[0].enabled);
    assert!(rig.engine.lock().unwrap().breakpoints.is_empty());
    rig.send(DebugAction::SetBreakpointEnabled {
        addr: CODE + 16,
        enabled: true,
    });
    rig.pump();
    assert_eq!(rig.engine.lock().unwrap().breakpoints, [CODE + 16]);
    rig.send(DebugAction::RemoveBreakpoint { addr: CODE + 16 });
    rig.pump();
    assert!(rig.view().breakpoints.is_empty());
    assert!(rig.engine.lock().unwrap().breakpoints.is_empty());

    // Hardware kinds are not offered by this guest yet.
    rig.send(DebugAction::AddBreakpoint {
        addr: CODE,
        kind: BreakpointKind::Hardware,
    });
    rig.pump();
    assert!(
        rig.view()
            .notice
            .as_deref()
            .unwrap()
            .contains("not available")
    );
}

#[test]
fn the_panel_and_a_client_share_one_breakpoint_table() {
    let mut rig = Rig::new();
    rig.stopped();
    let pid = rig.target.current;
    let inferior = rig.target.get(pid).unwrap();
    inferior
        .with_registry(|registry, backend| registry.panel_breakpoint(backend, CODE + 8, true))
        .unwrap();
    // The client sets and removes the same address: the guest's stays.
    assert!(
        inferior
            .with_registry(|r, b| r.client_add_sw(b, CODE + 8, 1))
            .is_ok()
    );
    assert_eq!(rig.count("set"), 1, "the guest was asked once");
    let inferior = rig.target.get(pid).unwrap();
    assert!(
        inferior
            .with_registry(|r, b| r.client_remove_sw(b, CODE + 8, 1))
            .unwrap()
    );
    assert_eq!(rig.engine.lock().unwrap().breakpoints, [CODE + 8]);
    // A client's own breakpoint goes when it leaves; the panel's does not.
    let inferior = rig.target.get(pid).unwrap();
    inferior
        .with_registry(|r, b| r.client_add_sw(b, CODE + 12, 1))
        .unwrap();
    inferior.with_registry(|r, b| r.clear_client(b));
    assert_eq!(rig.engine.lock().unwrap().breakpoints, [CODE + 8]);
    // Releasing the panel's interest clears the guest's.
    let inferior = rig.target.get(pid).unwrap();
    inferior
        .with_registry(|r, b| r.panel_breakpoint(b, CODE + 8, false))
        .unwrap();
    assert!(rig.engine.lock().unwrap().breakpoints.is_empty());
    // A client cannot remove one it never set.
    let inferior = rig.target.get(pid).unwrap();
    inferior
        .with_registry(|r, b| r.panel_breakpoint(b, CODE + 20, true))
        .unwrap();
    assert!(
        !inferior
            .with_registry(|r, b| r.client_remove_sw(b, CODE + 20, 1))
            .unwrap()
    );
    assert_eq!(rig.engine.lock().unwrap().breakpoints, [CODE + 20]);
}

#[test]
fn memory_reads_are_bounded_and_repeated_at_the_next_stop() {
    let mut rig = Rig::new();
    rig.stopped();
    rig.send(DebugAction::ReadMemory {
        addr: STACK + 0x10,
        size: 4097,
    });
    rig.pump();
    assert!(rig.view().memory.is_none());
    assert!(rig.view().notice.as_deref().unwrap().contains("4096"));
    rig.send(DebugAction::ReadMemory {
        addr: STACK + 0x10,
        size: 64,
    });
    rig.pump();
    let view = rig.view();
    let memory = view.window(WindowKind::Memory).unwrap();
    assert_eq!((memory.address, memory.bytes.len()), (STACK + 0x10, 64));
    // An unreadable range is an error in the window, not a failure.
    rig.send(DebugAction::ReadMemory {
        addr: 0x10,
        size: 16,
    });
    rig.pump();
    let view = rig.view();
    let memory = view.window(WindowKind::Memory).unwrap();
    assert!(memory.bytes.is_empty());
    assert_eq!(memory.error.as_deref(), Some("address not accessible"));
    // Step: the range is read again at the new stop.
    rig.send(DebugAction::Step { tid: TID });
    rig.pump_until(|view| view.window(WindowKind::Memory).is_some());
    assert_eq!(rig.view().window(WindowKind::Memory).unwrap().address, 0x10);
}

#[test]
fn selecting_a_thread_reads_its_registers_only() {
    let mut rig = Rig::new();
    rig.stopped();
    let threads = rig.count("threads");
    rig.send(DebugAction::SelectThread { tid: TID + 1 });
    rig.pump();
    let view = rig.view();
    assert_eq!(view.selected_tid, Some(TID + 1));
    assert_eq!(view.registers.as_ref().unwrap().tid, TID + 1);
    assert_eq!(view.registers.as_ref().unwrap().get("rip"), Some(0x40_1100));
    assert_eq!(rig.count("threads"), threads, "the thread list is kept");
    rig.send(DebugAction::SelectThread { tid: 9999 });
    rig.pump();
    assert!(
        rig.view()
            .notice
            .as_deref()
            .unwrap()
            .contains("not in the list")
    );
}

#[test]
fn a_process_that_exits_ends_the_controller() {
    let mut rig = Rig::new();
    rig.stopped();
    rig.send(DebugAction::Continue);
    rig.pump();
    rig.engine.lock().unwrap().state = TargetState::Exited { wait_status: 0x300 };
    let until = Instant::now() + Duration::from_secs(5);
    let ended = loop {
        match rig.pump() {
            Pump::Ended(why) => break why,
            Pump::Idle => assert!(Instant::now() < until),
        }
    };
    assert_eq!(ended, "the process exited with status 3");
    assert_eq!(rig.view().run, RunState::Exited { wait_status: 0x300 });
    assert_eq!(rig.pump(), Pump::Idle, "nothing more to do");
}

#[test]
fn a_slow_stop_is_reported_without_giving_up() {
    let mut rig = Rig::new();
    rig.control
        .timing(Duration::ZERO, Duration::ZERO, Duration::from_millis(1));
    rig.pump();
    // The fake never stops on interrupt: pretend the group is stuck.
    rig.engine.lock().unwrap().state = TargetState::Transition;
    rig.send(DebugAction::Stop);
    rig.pump();
    std::thread::sleep(Duration::from_millis(5));
    rig.pump();
    let view = rig.view();
    assert_eq!(
        view.run,
        RunState::Running {
            pending: Pending::Nothing
        }
    );
    assert!(view.notice.is_some());
    // It still stops when the guest gets there.
    rig.engine.lock().unwrap().stop(StopKind::Interrupt);
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
}

#[test]
fn a_client_takes_control_and_the_panel_becomes_read_only() {
    let mut rig = Rig::new();
    rig.stopped();
    let queued = rig.send(DebugAction::Refresh);
    rig.control.client_arrived();
    let view = rig.view();
    assert_eq!(view.controller, Controller::Gdb);
    assert!(!view.app_controls());
    assert_eq!(view.run, RunState::Unknown);
    assert!(view.registers.is_none());
    assert!(view.handled >= queued, "the queued request was dropped");
    assert!(rig.handle.client_connected());
    let refused = rig
        .handle
        .submit(DebugRequest {
            id: 99,
            sequence: 1,
            action: DebugAction::Continue,
        })
        .unwrap_err();
    assert!(refused.contains("external debugger"), "{refused}");
    // While the client has the process the controller does nothing.
    let before = rig.calls().len();
    rig.pump();
    assert_eq!(rig.calls().len(), before);

    // The client leaves (the server resumes the process); the panel reads the
    // state again and is back in control.
    rig.engine.lock().unwrap().state = TargetState::Running;
    rig.control.client_left(&mut rig.target);
    rig.pump();
    let view = rig.view();
    assert_eq!(view.controller, Controller::App);
    assert_eq!(
        view.run,
        RunState::Running {
            pending: Pending::Nothing
        }
    );
    rig.send(DebugAction::Stop);
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
}

#[test]
fn a_full_queue_refuses_more_requests() {
    let rig = Rig::new();
    let mut accepted = 0;
    let mut refused = None;
    for id in 0..100 {
        match rig.handle.submit(DebugRequest {
            id,
            sequence: 0,
            action: DebugAction::Stop,
        }) {
            Ok(()) => accepted += 1,
            Err(message) => {
                refused = Some(message);
                break;
            }
        }
    }
    assert_eq!(accepted, 32);
    assert!(refused.unwrap().contains("busy"));
}

fn wait(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_real_client_connecting_takes_the_process_from_the_panel() {
    let engine = Engine::new();
    let directory =
        std::env::temp_dir().join(format!("ant-panel-test-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&directory).unwrap();
    let mut server =
        DebugServer::start(Box::new(Fake(engine.clone(), caps())), &directory).unwrap();
    let panel = server.panel().clone();

    // The panel drives: stop, then fetch.
    wait("the first view", || {
        matches!(panel.view().run, RunState::Running { .. })
    });
    panel
        .submit(DebugRequest {
            id: 1,
            sequence: 0,
            action: DebugAction::Stop,
        })
        .unwrap();
    wait("a stop", || {
        panel.view().run.stopped_sequence().is_some() && !panel.view().loading
    });
    assert_eq!(panel.view().controller, Controller::App);

    // gdb connects: the panel is read-only while it is connected.
    let client = TcpStream::connect(("127.0.0.1", server.endpoints().tcp_port)).unwrap();
    wait("the client to take control", || panel.client_connected());
    assert_eq!(panel.view().controller, Controller::Gdb);
    let error = panel
        .submit(DebugRequest {
            id: 2,
            sequence: 1,
            action: DebugAction::Continue,
        })
        .unwrap_err();
    assert!(error.contains("external debugger"));
    assert!(
        !engine
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call == "Continue"),
        "the refused request never reached the guest"
    );

    // The client goes away: the process is left running and the panel is back.
    drop(client);
    wait("the client to leave", || !panel.client_connected());
    wait("the panel to take over", || {
        panel.view().controller == Controller::App
            && matches!(panel.view().run, RunState::Running { .. })
    });
    assert!(
        engine
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|call| call == "Continue"),
        "the server resumed the process when the client left"
    );
    panel
        .submit(DebugRequest {
            id: 3,
            sequence: 0,
            action: DebugAction::Stop,
        })
        .unwrap();
    wait("the panel to stop it again", || {
        panel.view().run.stopped_sequence().is_some()
    });
    server
        .shutdown(DetachMode::Resume, Duration::from_secs(5))
        .unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn hardware_breakpoints_and_watchpoints_reach_the_guest_as_aligned_pieces() {
    let mut rig = Rig::hardware();
    rig.stopped();
    rig.send(DebugAction::AddBreakpoint {
        addr: CODE + 0x20,
        kind: BreakpointKind::Hardware,
    });
    // A write watch on an aligned 8 bytes is one piece; a read watch becomes an
    // access watch (the registers have no read-only mode); an unaligned one
    // is split.
    rig.send(DebugAction::AddBreakpoint {
        addr: STACK + 0x10,
        kind: BreakpointKind::Watch(WatchAccess::Write),
    });
    rig.send(DebugAction::AddBreakpoint {
        addr: STACK + 0x21,
        kind: BreakpointKind::Watch(WatchAccess::Read),
    });
    rig.pump();
    let calls = rig.calls();
    for want in [
        format!("hw+ Hardware {:#x} 1", CODE + 0x20),
        format!("hw+ Watch(Write) {:#x} 8", STACK + 0x10),
        format!("hw+ Watch(Access) {:#x} 1", STACK + 0x21),
        format!("hw+ Watch(Access) {:#x} 2", STACK + 0x22),
        format!("hw+ Watch(Access) {:#x} 4", STACK + 0x24),
        format!("hw+ Watch(Access) {:#x} 1", STACK + 0x28),
    ] {
        assert!(calls.contains(&want), "{want} missing in {calls:?}");
    }
    assert_eq!(rig.view().breakpoints.len(), 3);
    rig.send(DebugAction::RemoveBreakpoint { addr: STACK + 0x21 });
    rig.pump();
    assert!(rig.count("hw- Watch(Access)") == 4);
    // A guest without them still refuses, with its reason.
    let mut plain = Rig::new();
    plain.stopped();
    plain.send(DebugAction::AddBreakpoint {
        addr: CODE,
        kind: BreakpointKind::Hardware,
    });
    plain.pump();
    assert!(plain.view().breakpoints.is_empty());
    assert!(
        plain
            .view()
            .notice
            .as_deref()
            .unwrap_or("")
            .contains("not available")
    );
}

#[test]
fn a_thread_stopped_on_a_signal_gets_it_on_continue_or_step_except_a_trap() {
    let mut rig = Rig::new();
    rig.pump();
    {
        let mut engine = rig.engine.lock().unwrap();
        engine.stop(StopKind::Signal { signal: 11 });
    }
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
    assert!(matches!(
        rig.view().run,
        RunState::Stopped {
            reason: StopReason::Signal { number: 11 },
            ..
        }
    ));
    rig.send(DebugAction::Step { tid: TID });
    rig.pump();
    assert!(
        rig.calls()
            .contains(&format!("StepSignal {{ tid: {TID}, signal: 11 }}")),
        "{:?}",
        rig.calls()
    );
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
    // The step ended as a step: nothing left to pass.
    rig.send(DebugAction::Continue);
    rig.pump();
    assert!(rig.calls().contains(&"Continue".to_string()));
    {
        let mut engine = rig.engine.lock().unwrap();
        engine.stop(StopKind::Signal { signal: 5 });
    }
    rig.pump_until(|view| view.run.stopped_sequence().is_some() && !view.loading);
    rig.send(DebugAction::Continue);
    rig.pump();
    assert!(
        !rig.calls()
            .iter()
            .any(|call| call.starts_with("ContinueSignal")),
        "SIGTRAP is not passed: {:?}",
        rig.calls()
    );
}
