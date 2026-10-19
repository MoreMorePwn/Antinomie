// SPDX-License-Identifier: MIT
//! Encoders and decoders for the guest debug opcodes (`protocol/control.h`).
//! Pure functions: no transport, so every layout is unit-tested against the
//! shared header. All integers are little endian.
use super::target::{ArchTag, DebugCaps, RegsetBlob, RegsetInfo, StopEvent, StopKind};
use crate::control::header;

pub const CAPS: u32 = 0x1080;
pub const ATTACH: u32 = 0x1081;
pub const DETACH: u32 = 0x1082;
pub const STATUS: u32 = 0x1083;
pub const STOP: u32 = 0x1084;
pub const CONT: u32 = 0x1085;
pub const THREADS: u32 = 0x1086;
pub const REGS_READ: u32 = 0x1087;
pub const REGS_WRITE: u32 = 0x1088;
pub const MEM_READ: u32 = 0x1089;
pub const MEM_WRITE: u32 = 0x108a;
pub const BP_SET: u32 = 0x108b;
pub const BP_CLEAR: u32 = 0x108c;

pub const ABI: u32 = 1;
pub const CAPS_SIZE: usize = 48;
pub const REGSET_ENTRY_SIZE: usize = 16;
pub const REGSET_MAX: usize = 8;
pub const STATUS_SIZE: usize = 96;
pub const THREAD_ENTRY_SIZE: usize = 32;
pub const TRANSFER_MAX: usize = 16000;
pub const THREADS_MAX: usize = 256;

pub const ATTACH_STOP: u32 = 1;
pub const DETACH_KILL: u32 = 1;
pub const CONT_STEP: u32 = 1;

pub const CAP_SW_BREAKPOINT: u32 = 1;
pub const CAP_HW_SINGLE_STEP: u32 = 2;
pub const CAP_SHADOW_READS: u32 = 4;
pub const CAP_MULTI_THREAD: u32 = 8;
pub const CAP_HW_BREAKPOINT: u32 = 16;
pub const CAP_HW_WATCHPOINT: u32 = 32;

pub const STATE_RUNNING: u32 = 1;
pub const STATE_STOPPING: u32 = 2;
pub const STATE_STOPPED: u32 = 3;
pub const STATE_RESUMING: u32 = 4;
pub const STATE_EXITED: u32 = 5;
pub const STATE_EXEC: u32 = 6;
pub const STATE_DETACHING: u32 = 7;

pub const EVENT_NONE: u32 = 0;
pub const EVENT_INTERRUPT: u32 = 1;
pub const EVENT_BREAKPOINT: u32 = 2;
pub const EVENT_STEP: u32 = 3;
pub const EVENT_EXIT: u32 = 4;
pub const EVENT_EXEC: u32 = 5;

pub const BP_SOFTWARE: u32 = 1;

fn u32_at(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
        .ok_or_else(|| "debug reply is too short".to_string())
}
fn u64_at(data: &[u8], offset: usize) -> Result<u64, String> {
    data.get(offset..offset + 8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
        .ok_or_else(|| "debug reply is too short".to_string())
}

pub fn caps_request() -> Vec<u8> {
    header(0)
}

pub fn parse_caps(reply: &[u8]) -> Result<DebugCaps, String> {
    if reply.len() < CAPS_SIZE {
        return Err("debug capability reply is too short".into());
    }
    let abi = u32_at(reply, 0)?;
    if abi != ABI {
        return Err(format!("unsupported debug ABI {abi}"));
    }
    let arch = ArchTag::from_e_machine(u32_at(reply, 4)?).ok_or_else(|| {
        format!(
            "unsupported guest architecture {}",
            u32_at(reply, 4).unwrap_or(0)
        )
    })?;
    let flags = u32_at(reply, 8)?;
    let known = CAP_SW_BREAKPOINT
        | CAP_HW_SINGLE_STEP
        | CAP_SHADOW_READS
        | CAP_MULTI_THREAD
        | CAP_HW_BREAKPOINT
        | CAP_HW_WATCHPOINT;
    if flags & !known != 0 || reply[40..48] != [0; 8] {
        return Err("debug capability reply has unknown fields".into());
    }
    let count = u32_at(reply, 36)? as usize;
    if count > REGSET_MAX || reply.len() != CAPS_SIZE + count * REGSET_ENTRY_SIZE {
        return Err("debug capability reply has a bad register-set table".into());
    }
    let mut regsets = Vec::with_capacity(count);
    for index in 0..count {
        let entry = CAPS_SIZE + index * REGSET_ENTRY_SIZE;
        let entry_flags = u32_at(reply, entry + 8)?;
        if entry_flags & !1 != 0 || u32_at(reply, entry + 12)? != 0 {
            return Err("debug register-set entry has unknown fields".into());
        }
        regsets.push(RegsetInfo {
            nt_type: u32_at(reply, entry)?,
            max_size: u32_at(reply, entry + 4)?,
            writable: entry_flags & 1 != 0,
        });
    }
    let max_transfer = u32_at(reply, 32)?;
    if max_transfer == 0 || max_transfer as usize > TRANSFER_MAX {
        return Err("debug transfer size is out of range".into());
    }
    Ok(DebugCaps {
        abi,
        arch,
        software_breakpoints: flags & CAP_SW_BREAKPOINT != 0,
        hardware_single_step: flags & CAP_HW_SINGLE_STEP != 0,
        shadow_reads: flags & CAP_SHADOW_READS != 0,
        multi_thread: flags & CAP_MULTI_THREAD != 0,
        hardware_breakpoints: u32_at(reply, 16)?,
        hardware_watchpoints: u32_at(reply, 20)?,
        breakpoint_len_mask: u32_at(reply, 12)?,
        watch_len_mask: u32_at(reply, 24)?,
        max_threads: u32_at(reply, 28)?,
        max_transfer,
        regsets,
    })
}

pub struct AttachRequest {
    pub task_cookie: u64,
    pub start_boot_ns: u64,
    pub tgid: u32,
    pub arch: ArchTag,
    pub nonce: [u64; 2],
    pub stop_now: bool,
}
pub fn attach_request(request: &AttachRequest) -> Result<Vec<u8>, String> {
    if request.task_cookie == 0 || request.tgid == 0 || request.nonce == [0, 0] {
        return Err("debug attach needs a task cookie, PID and a nonzero nonce".into());
    }
    let mut args = header(if request.stop_now { ATTACH_STOP } else { 0 });
    args.extend(request.task_cookie.to_le_bytes());
    args.extend(request.start_boot_ns.to_le_bytes());
    args.extend(request.tgid.to_le_bytes());
    args.extend(request.arch.e_machine().to_le_bytes());
    args.extend(request.nonce[0].to_le_bytes());
    args.extend(request.nonce[1].to_le_bytes());
    Ok(args)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachReply {
    pub session: u64,
    pub generation: u64,
    pub threads: u32,
    pub arch: ArchTag,
}
pub fn parse_attach(reply: &[u8]) -> Result<AttachReply, String> {
    if reply.len() != 24 {
        return Err("debug attach reply has the wrong length".into());
    }
    let session = u64_at(reply, 0)?;
    if session == 0 {
        return Err("debug attach returned no session".into());
    }
    Ok(AttachReply {
        session,
        generation: u64_at(reply, 8)?,
        threads: u32_at(reply, 16)?,
        arch: ArchTag::from_e_machine(u32_at(reply, 20)?)
            .ok_or("debug attach reported an unknown architecture")?,
    })
}

fn with_session(flags: u32, session: u64) -> Vec<u8> {
    let mut args = header(flags);
    args.extend(session.to_le_bytes());
    args
}
pub fn status_request(session: u64) -> Vec<u8> {
    with_session(0, session)
}
pub fn stop_request(session: u64) -> Vec<u8> {
    with_session(0, session)
}
pub fn threads_request(session: u64) -> Vec<u8> {
    with_session(0, session)
}
pub fn detach_request(session: u64, kill: bool) -> Vec<u8> {
    with_session(if kill { DETACH_KILL } else { 0 }, session)
}
pub fn cont_request(session: u64, step_tid: Option<u32>, generation: u64) -> Vec<u8> {
    let mut args = with_session(if step_tid.is_some() { CONT_STEP } else { 0 }, session);
    args.extend(u64::from(step_tid.unwrap_or(0)).to_le_bytes());
    args.extend(0u32.to_le_bytes());
    args.extend(0u32.to_le_bytes());
    args.extend(generation.to_le_bytes());
    args
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    pub session: u64,
    pub generation: u64,
    pub state: u32,
    pub threads: u32,
    pub stopped_threads: u32,
    pub event_kind: u32,
    pub event_tid: u32,
    pub event_pc: u64,
    pub event_addr: u64,
    pub wait_status: u32,
    pub last_error: i32,
    pub event_sequence: u32,
    pub breakpoints: u32,
}
impl SessionStatus {
    pub fn stop_event(&self) -> Option<StopEvent> {
        let kind = match self.event_kind {
            EVENT_INTERRUPT => StopKind::Interrupt,
            EVENT_BREAKPOINT => StopKind::Breakpoint {
                addr: self.event_addr,
            },
            EVENT_STEP => StopKind::Step,
            _ => return None,
        };
        Some(StopEvent {
            sequence: self.event_sequence,
            kind,
            tid: self.event_tid,
            pc: self.event_pc,
        })
    }
}
pub fn parse_status(reply: &[u8]) -> Result<SessionStatus, String> {
    if reply.len() != STATUS_SIZE || reply[72..96] != [0; 24] || u32_at(reply, 20)? != 0 {
        return Err("debug status reply is malformed".into());
    }
    let state = u32_at(reply, 16)?;
    if !(STATE_RUNNING..=STATE_DETACHING).contains(&state) {
        return Err("debug status reports an unknown state".into());
    }
    Ok(SessionStatus {
        session: u64_at(reply, 0)?,
        generation: u64_at(reply, 8)?,
        state,
        threads: u32_at(reply, 24)?,
        stopped_threads: u32_at(reply, 28)?,
        event_kind: u32_at(reply, 32)?,
        event_tid: u32_at(reply, 36)?,
        event_pc: u64_at(reply, 40)?,
        event_addr: u64_at(reply, 48)?,
        wait_status: u32_at(reply, 56)?,
        last_error: u32_at(reply, 60)? as i32,
        event_sequence: u32_at(reply, 64)?,
        breakpoints: u32_at(reply, 68)?,
    })
}

pub fn parse_cont(reply: &[u8]) -> Result<u64, String> {
    if reply.len() != 8 {
        return Err("debug continue reply has the wrong length".into());
    }
    u64_at(reply, 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadEntry {
    pub tid: u32,
    pub stopped: bool,
    pub stop_reason: u32,
    pub pc: u64,
}
pub fn parse_threads(reply: &[u8]) -> Result<Vec<ThreadEntry>, String> {
    let count = u32_at(reply, 0)? as usize;
    let total = u32_at(reply, 4)? as usize;
    if count > THREADS_MAX || total < count || reply.len() != 8 + count * THREAD_ENTRY_SIZE {
        return Err("debug thread list is malformed".into());
    }
    (0..count)
        .map(|index| {
            let entry = 8 + index * THREAD_ENTRY_SIZE;
            let tid = u32_at(reply, entry)?;
            let state = u32_at(reply, entry + 4)?;
            if tid == 0 || !(1..=2).contains(&state) || reply[entry + 24..entry + 32] != [0; 8] {
                return Err("debug thread entry is malformed".to_string());
            }
            Ok(ThreadEntry {
                tid,
                stopped: state == 2,
                stop_reason: u32_at(reply, entry + 8)?,
                pc: u64_at(reply, entry + 16)?,
            })
        })
        .collect()
}

fn regs_header(session: u64, tid: u32, nt_type: u32, generation: u64) -> Vec<u8> {
    let mut args = with_session(0, session);
    args.extend(tid.to_le_bytes());
    args.extend(nt_type.to_le_bytes());
    args.extend(generation.to_le_bytes());
    args
}
pub fn regs_read_request(session: u64, tid: u32, nt_type: u32, generation: u64) -> Vec<u8> {
    regs_header(session, tid, nt_type, generation)
}
pub fn regs_write_request(
    session: u64,
    tid: u32,
    blob: &RegsetBlob,
    generation: u64,
) -> Result<Vec<u8>, String> {
    let length = u32::try_from(blob.data.len()).map_err(|_| "register blob too large")?;
    if blob.data.is_empty() || blob.data.len() > TRANSFER_MAX {
        return Err("register blob size is out of range".into());
    }
    let mut args = regs_header(session, tid, blob.nt_type, generation);
    args.extend(length.to_le_bytes());
    args.extend(0u32.to_le_bytes());
    args.extend(&blob.data);
    Ok(args)
}
pub fn parse_regs(reply: &[u8], nt_type: u32) -> Result<RegsetBlob, String> {
    let length = u32_at(reply, 4)? as usize;
    if reply.len() < 16 || u32_at(reply, 0)? != nt_type || reply.len() != 16 + length {
        return Err("debug register reply is malformed".into());
    }
    Ok(RegsetBlob {
        nt_type,
        data: reply[16..].to_vec(),
    })
}

fn memory_header(session: u64, addr: u64, len: u32, generation: u64) -> Vec<u8> {
    let mut args = with_session(0, session);
    args.extend(addr.to_le_bytes());
    args.extend(len.to_le_bytes());
    args.extend(0u32.to_le_bytes());
    args.extend(generation.to_le_bytes());
    args
}
pub fn mem_read_request(
    session: u64,
    addr: u64,
    len: usize,
    generation: u64,
) -> Result<Vec<u8>, String> {
    if len == 0 || len > TRANSFER_MAX {
        return Err("memory read length is out of range".into());
    }
    Ok(memory_header(session, addr, len as u32, generation))
}
pub fn mem_write_request(
    session: u64,
    addr: u64,
    data: &[u8],
    generation: u64,
) -> Result<Vec<u8>, String> {
    if data.is_empty() || data.len() > TRANSFER_MAX {
        return Err("memory write length is out of range".into());
    }
    let mut args = memory_header(session, addr, data.len() as u32, generation);
    args.extend(data);
    Ok(args)
}
pub fn parse_mem_read(reply: &[u8], requested: usize) -> Result<Vec<u8>, String> {
    let count = u32_at(reply, 0)? as usize;
    if count == 0 || count > requested || reply.len() != 8 + count || u32_at(reply, 4)? != 0 {
        return Err("debug memory reply is malformed".into());
    }
    Ok(reply[8..].to_vec())
}
pub fn parse_mem_write(reply: &[u8], requested: usize) -> Result<(), String> {
    if reply.len() != 8 || u32_at(reply, 0)? as usize != requested {
        return Err("debug memory write was not complete".into());
    }
    Ok(())
}

pub fn breakpoint_request(session: u64, addr: u64, len: u32, generation: u64) -> Vec<u8> {
    let mut args = with_session(0, session);
    args.extend(BP_SOFTWARE.to_le_bytes());
    args.extend(len.to_le_bytes());
    args.extend(addr.to_le_bytes());
    args.extend(generation.to_le_bytes());
    args
}
