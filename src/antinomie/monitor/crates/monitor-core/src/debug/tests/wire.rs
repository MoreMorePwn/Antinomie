// SPDX-License-Identifier: GPL-3.0-only
use crate::debug::{ArchTag, RegsetBlob, wire::*};

fn define(name: &str) -> u32 {
    let header = include_str!("../../../../../protocol/control.h");
    let line = header
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(name))
        .unwrap_or_else(|| panic!("{name} missing from the shared header"));
    let value = line.split_whitespace().nth(2).unwrap();
    match value.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).unwrap(),
        None => value.parse().unwrap(),
    }
}

#[test]
fn constants_match_the_shared_control_header() {
    for (name, value) in [
        ("ANTC_DEBUG_CAPS", CAPS),
        ("ANTC_DEBUG_ATTACH", ATTACH),
        ("ANTC_DEBUG_DETACH", DETACH),
        ("ANTC_DEBUG_STATUS", STATUS),
        ("ANTC_DEBUG_STOP", STOP),
        ("ANTC_DEBUG_CONT", CONT),
        ("ANTC_DEBUG_THREADS", THREADS),
        ("ANTC_DEBUG_REGS_READ", REGS_READ),
        ("ANTC_DEBUG_REGS_WRITE", REGS_WRITE),
        ("ANTC_DEBUG_MEM_READ", MEM_READ),
        ("ANTC_DEBUG_MEM_WRITE", MEM_WRITE),
        ("ANTC_DEBUG_BP_SET", BP_SET),
        ("ANTC_DEBUG_BP_CLEAR", BP_CLEAR),
        ("ANTC_DEBUG_ABI", ABI),
        ("ANTC_DEBUG_CAPS_SIZE", CAPS_SIZE as u32),
        ("ANTC_DEBUG_REGSET_SIZE", REGSET_ENTRY_SIZE as u32),
        ("ANTC_DEBUG_REGSET_MAX", REGSET_MAX as u32),
        ("ANTC_DEBUG_STATUS_SIZE", STATUS_SIZE as u32),
        ("ANTC_DEBUG_THREAD_SIZE", THREAD_ENTRY_SIZE as u32),
        ("ANTC_DEBUG_TRANSFER_MAX", TRANSFER_MAX as u32),
        ("ANTC_DEBUG_ATTACH_STOP", ATTACH_STOP),
        ("ANTC_DEBUG_DETACH_KILL", DETACH_KILL),
        ("ANTC_DEBUG_CONT_STEP", CONT_STEP),
        ("ANTC_DEBUG_CAP_SW_BREAKPOINT", CAP_SW_BREAKPOINT),
        ("ANTC_DEBUG_CAP_HW_SINGLE_STEP", CAP_HW_SINGLE_STEP),
        ("ANTC_DEBUG_CAP_SHADOW_READS", CAP_SHADOW_READS),
        ("ANTC_DEBUG_CAP_MULTI_THREAD", CAP_MULTI_THREAD),
        ("ANTC_DEBUG_CAP_HW_BREAKPOINT", CAP_HW_BREAKPOINT),
        ("ANTC_DEBUG_CAP_HW_WATCHPOINT", CAP_HW_WATCHPOINT),
        ("ANTC_DEBUG_RUNNING", STATE_RUNNING),
        ("ANTC_DEBUG_STOPPING", STATE_STOPPING),
        ("ANTC_DEBUG_STOPPED", STATE_STOPPED),
        ("ANTC_DEBUG_RESUMING", STATE_RESUMING),
        ("ANTC_DEBUG_EXITED", STATE_EXITED),
        ("ANTC_DEBUG_EXEC", STATE_EXEC),
        ("ANTC_DEBUG_DETACHING", STATE_DETACHING),
        ("ANTC_DEBUG_EVENT_NONE", EVENT_NONE),
        ("ANTC_DEBUG_EVENT_INTERRUPT", EVENT_INTERRUPT),
        ("ANTC_DEBUG_EVENT_BREAKPOINT", EVENT_BREAKPOINT),
        ("ANTC_DEBUG_EVENT_STEP", EVENT_STEP),
        ("ANTC_DEBUG_EVENT_EXIT", EVENT_EXIT),
        ("ANTC_DEBUG_EVENT_EXEC", EVENT_EXEC),
        ("ANTC_DEBUG_BP_SOFTWARE", BP_SOFTWARE),
    ] {
        assert_eq!(define(name), value, "{name}");
    }
}

fn caps_reply(regsets: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut reply = vec![0u8; CAPS_SIZE];
    reply[0..4].copy_from_slice(&1u32.to_le_bytes());
    reply[4..8].copy_from_slice(&62u32.to_le_bytes());
    reply[8..12].copy_from_slice(
        &(CAP_SW_BREAKPOINT | CAP_HW_SINGLE_STEP | CAP_MULTI_THREAD).to_le_bytes(),
    );
    reply[12..16].copy_from_slice(&1u32.to_le_bytes());
    reply[28..32].copy_from_slice(&256u32.to_le_bytes());
    reply[32..36].copy_from_slice(&16000u32.to_le_bytes());
    reply[36..40].copy_from_slice(&(regsets.len() as u32).to_le_bytes());
    for (nt, size, flags) in regsets {
        reply.extend(nt.to_le_bytes());
        reply.extend(size.to_le_bytes());
        reply.extend(flags.to_le_bytes());
        reply.extend(0u32.to_le_bytes());
    }
    reply
}

#[test]
fn capability_reply_is_validated() {
    let reply = caps_reply(&[(1, 216, 1), (2, 512, 1), (0x202, 0, 0)]);
    let caps = parse_caps(&reply, false).unwrap();
    assert_eq!(caps.arch, ArchTag::X86_64);
    assert!(caps.software_breakpoints && caps.hardware_single_step && caps.multi_thread);
    assert!(!caps.shadow_reads);
    assert!(caps.supports_breakpoint_len(1) && !caps.supports_breakpoint_len(2));
    assert_eq!(caps.regsets.len(), 3);
    assert!(caps.regset(1).unwrap().writable && !caps.regset(0x202).unwrap().writable);
    for len in 0..reply.len() {
        assert!(parse_caps(&reply[..len], false).is_err(), "length {len}");
    }
    let mut bad = reply.clone();
    bad[0] = 2;
    assert!(parse_caps(&bad, false).is_err(), "unknown ABI");
    let mut bad = reply.clone();
    bad[4] = 40;
    assert!(parse_caps(&bad, false).is_err(), "unknown architecture");
    let mut bad = reply.clone();
    bad[11] = 0x80;
    assert!(parse_caps(&bad, false).is_err(), "unknown capability flag");
    let mut bad = reply.clone();
    bad[32..36].copy_from_slice(&16001u32.to_le_bytes());
    assert!(
        parse_caps(&bad, false).is_err(),
        "transfer size over the bound"
    );
    let mut bad = reply.clone();
    bad[36..40].copy_from_slice(&9u32.to_le_bytes());
    assert!(
        parse_caps(&bad, false).is_err(),
        "table longer than the maximum"
    );
    let mut bad = reply;
    bad[CAPS_SIZE + 8] = 2;
    assert!(
        parse_caps(&bad, false).is_err(),
        "unknown register-set flag"
    );
}

#[test]
fn attach_request_layout() {
    let request = AttachRequest {
        task_cookie: 0x1122_3344_5566_7788,
        start_boot_ns: 9,
        tgid: 95,
        arch: ArchTag::X86_64,
        nonce: [3, 4],
        stop_now: true,
        adopt: false,
    };
    let args = attach_request(&request).unwrap();
    assert_eq!(args.len(), 48);
    assert_eq!(&args[..4], &[1, 0, 8, 0]);
    assert_eq!(
        u32::from_le_bytes(args[4..8].try_into().unwrap()),
        ATTACH_STOP
    );
    assert_eq!(
        u64::from_le_bytes(args[8..16].try_into().unwrap()),
        request.task_cookie
    );
    assert_eq!(u64::from_le_bytes(args[16..24].try_into().unwrap()), 9);
    assert_eq!(u32::from_le_bytes(args[24..28].try_into().unwrap()), 95);
    assert_eq!(u32::from_le_bytes(args[28..32].try_into().unwrap()), 62);
    assert_eq!(u64::from_le_bytes(args[32..40].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(args[40..48].try_into().unwrap()), 4);
    for broken in [
        AttachRequest {
            task_cookie: 0,
            ..request_copy(&request)
        },
        AttachRequest {
            tgid: 0,
            ..request_copy(&request)
        },
        AttachRequest {
            nonce: [0, 0],
            ..request_copy(&request)
        },
    ] {
        assert!(attach_request(&broken).is_err());
    }
}
fn request_copy(request: &AttachRequest) -> AttachRequest {
    AttachRequest {
        task_cookie: request.task_cookie,
        start_boot_ns: request.start_boot_ns,
        tgid: request.tgid,
        arch: request.arch,
        nonce: request.nonce,
        stop_now: request.stop_now,
        adopt: request.adopt,
    }
}

#[test]
fn attach_and_cont_replies() {
    let mut reply = vec![0u8; 24];
    reply[0..8].copy_from_slice(&7u64.to_le_bytes());
    reply[8..16].copy_from_slice(&1u64.to_le_bytes());
    reply[16..20].copy_from_slice(&3u32.to_le_bytes());
    reply[20..24].copy_from_slice(&62u32.to_le_bytes());
    let attached = parse_attach(&reply).unwrap();
    assert_eq!((attached.session, attached.threads), (7, 3));
    for len in [0, 8, 23, 25] {
        assert!(parse_attach(&vec![0; len]).is_err());
    }
    reply[0..8].fill(0);
    assert!(parse_attach(&reply).is_err(), "session id zero");
    assert_eq!(parse_cont(&5u64.to_le_bytes()).unwrap(), 5);
    assert!(parse_cont(&[0; 7]).is_err());
}

#[test]
fn control_requests_layout() {
    let cont = cont_request(7, Some(95), 4, None);
    assert_eq!(cont.len(), 40);
    assert_eq!(
        u32::from_le_bytes(cont[4..8].try_into().unwrap()),
        CONT_STEP
    );
    assert_eq!(u64::from_le_bytes(cont[8..16].try_into().unwrap()), 7);
    assert_eq!(u64::from_le_bytes(cont[16..24].try_into().unwrap()), 95);
    assert_eq!(cont[24..32], [0; 8]);
    assert_eq!(u64::from_le_bytes(cont[32..40].try_into().unwrap()), 4);
    let plain = cont_request(7, None, 4, None);
    assert_eq!(u32::from_le_bytes(plain[4..8].try_into().unwrap()), 0);
    // A signal for thread 95: number at 24, thread at 28.
    let signalled = cont_request(7, None, 4, Some((95, 11)));
    assert_eq!(
        u32::from_le_bytes(signalled[24..28].try_into().unwrap()),
        11
    );
    assert_eq!(
        u32::from_le_bytes(signalled[28..32].try_into().unwrap()),
        95
    );
    assert_eq!(u32::from_le_bytes(signalled[20..24].try_into().unwrap()), 0);
    assert_eq!(detach_request(7, true).len(), 16);
    assert_eq!(
        u32::from_le_bytes(detach_request(7, true)[4..8].try_into().unwrap()),
        DETACH_KILL
    );
    assert_eq!(status_request(7).len(), 16);
    let bp = breakpoint_request(7, 0x401000, 1, 9);
    assert_eq!(bp.len(), 40);
    assert_eq!(
        u32::from_le_bytes(bp[16..20].try_into().unwrap()),
        BP_SOFTWARE
    );
    assert_eq!(u32::from_le_bytes(bp[20..24].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bp[24..32].try_into().unwrap()), 0x401000);
    assert_eq!(u64::from_le_bytes(bp[32..40].try_into().unwrap()), 9);
}

#[test]
fn status_reply_is_validated() {
    let mut reply = vec![0u8; STATUS_SIZE];
    reply[0..8].copy_from_slice(&7u64.to_le_bytes());
    reply[8..16].copy_from_slice(&5u64.to_le_bytes());
    reply[16..20].copy_from_slice(&STATE_STOPPED.to_le_bytes());
    reply[24..28].copy_from_slice(&3u32.to_le_bytes());
    reply[28..32].copy_from_slice(&3u32.to_le_bytes());
    reply[32..36].copy_from_slice(&EVENT_BREAKPOINT.to_le_bytes());
    reply[36..40].copy_from_slice(&95u32.to_le_bytes());
    reply[40..48].copy_from_slice(&0x4018c0u64.to_le_bytes());
    reply[48..56].copy_from_slice(&0x4018c0u64.to_le_bytes());
    reply[60..64].copy_from_slice(&(-110i32).to_le_bytes());
    reply[64..68].copy_from_slice(&2u32.to_le_bytes());
    let status = parse_status(&reply).unwrap();
    assert_eq!(status.state, STATE_STOPPED);
    assert_eq!(status.last_error, -110);
    let event = status.stop_event().unwrap();
    assert_eq!((event.tid, event.pc, event.sequence), (95, 0x4018c0, 2));
    assert!(matches!(
        event.kind,
        crate::debug::StopKind::Breakpoint { addr: 0x4018c0 }
    ));
    for len in 0..STATUS_SIZE {
        assert!(parse_status(&reply[..len]).is_err());
    }
    let mut bad = reply.clone();
    bad[16] = 9;
    assert!(parse_status(&bad).is_err(), "unknown state");
    let mut bad = reply.clone();
    bad[85] = 1;
    assert!(parse_status(&bad).is_err(), "unknown session flag");
    let mut bad = reply.clone();
    bad[81] = 1;
    assert!(parse_status(&bad).is_err(), "unknown option");
    let mut child = reply.clone();
    child[80..84].copy_from_slice(&(OPT_FORK | OPT_EXEC).to_le_bytes());
    child[84..88].copy_from_slice(&(SF_CHILD_PENDING | SF_SHARED_MM).to_le_bytes());
    child[88..96].copy_from_slice(&4u64.to_le_bytes());
    let status = parse_status(&child).unwrap();
    assert!(status.is_child_pending());
    assert_eq!((status.options, status.parent_session), (3, 4));
    let mut signal = reply.clone();
    signal[32..36].copy_from_slice(&EVENT_SIGNAL.to_le_bytes());
    signal[72..76].copy_from_slice(&11u32.to_le_bytes());
    assert!(matches!(
        parse_status(&signal).unwrap().stop_event().unwrap().kind,
        crate::debug::StopKind::Signal { signal: 11 }
    ));
    let mut exited = reply;
    exited[32..36].copy_from_slice(&EVENT_EXIT.to_le_bytes());
    assert!(parse_status(&exited).unwrap().stop_event().is_none());
}

#[test]
fn thread_list_is_validated() {
    let mut reply = vec![0u8; 8];
    reply[0..4].copy_from_slice(&2u32.to_le_bytes());
    reply[4..8].copy_from_slice(&2u32.to_le_bytes());
    for (tid, state, pc) in [(95u32, 2u32, 0x401000u64), (96, 1, 0)] {
        let mut entry = vec![0u8; THREAD_ENTRY_SIZE];
        entry[0..4].copy_from_slice(&tid.to_le_bytes());
        entry[4..8].copy_from_slice(&state.to_le_bytes());
        entry[16..24].copy_from_slice(&pc.to_le_bytes());
        reply.extend(entry);
    }
    let threads = parse_threads(&reply).unwrap();
    assert_eq!(threads.len(), 2);
    assert!(threads[0].stopped && !threads[1].stopped);
    for len in 0..reply.len() {
        assert!(parse_threads(&reply[..len]).is_err());
    }
    let mut bad = reply.clone();
    bad[8..12].fill(0);
    assert!(parse_threads(&bad).is_err(), "tid zero");
    let mut bad = reply.clone();
    bad[12] = 7;
    assert!(parse_threads(&bad).is_err(), "unknown thread state");
    let mut bad = reply;
    bad[4..8].copy_from_slice(&1u32.to_le_bytes());
    assert!(parse_threads(&bad).is_err(), "total below count");
}

#[test]
fn register_and_memory_requests_round_trip() {
    let read = regs_read_request(7, 95, 1, 3);
    assert_eq!(read.len(), 32);
    assert_eq!(u32::from_le_bytes(read[16..20].try_into().unwrap()), 95);
    assert_eq!(u32::from_le_bytes(read[20..24].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(read[24..32].try_into().unwrap()), 3);
    let blob = RegsetBlob {
        nt_type: 1,
        data: vec![0xab; 216],
    };
    let write = regs_write_request(7, 95, &blob, 3).unwrap();
    assert_eq!(write.len(), 40 + 216);
    assert_eq!(u32::from_le_bytes(write[32..36].try_into().unwrap()), 216);
    assert!(
        regs_write_request(
            7,
            95,
            &RegsetBlob {
                nt_type: 1,
                data: vec![]
            },
            3
        )
        .is_err()
    );
    assert!(
        regs_write_request(
            7,
            95,
            &RegsetBlob {
                nt_type: 1,
                data: vec![0; TRANSFER_MAX + 1]
            },
            3
        )
        .is_err()
    );
    let mut reply = vec![0u8; 16];
    reply[0..4].copy_from_slice(&1u32.to_le_bytes());
    reply[4..8].copy_from_slice(&4u32.to_le_bytes());
    reply.extend([1, 2, 3, 4]);
    assert_eq!(parse_regs(&reply, 1).unwrap().data, vec![1, 2, 3, 4]);
    assert!(parse_regs(&reply, 2).is_err(), "other note type");
    assert!(parse_regs(&reply[..19], 1).is_err(), "length mismatch");

    assert_eq!(mem_read_request(7, 0x1000, 64, 3).unwrap().len(), 40);
    assert!(mem_read_request(7, 0x1000, 0, 3).is_err());
    assert!(mem_read_request(7, 0x1000, TRANSFER_MAX + 1, 3).is_err());
    let write = mem_write_request(7, 0x1000, &[1, 2, 3], 3).unwrap();
    assert_eq!(write.len(), 43);
    assert_eq!(u32::from_le_bytes(write[24..28].try_into().unwrap()), 3);
    assert!(mem_write_request(7, 0x1000, &[], 3).is_err());
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    data.extend([9, 8, 7, 6]);
    assert_eq!(parse_mem_read(&data, 8).unwrap(), vec![9, 8, 7, 6]);
    assert!(parse_mem_read(&data, 3).is_err(), "more than asked");
    assert!(parse_mem_read(&data[..11], 8).is_err(), "truncated");
    data[0..4].fill(0);
    assert!(parse_mem_read(&data, 8).is_err(), "nothing read");
    let mut written = vec![0u8; 8];
    written[0..4].copy_from_slice(&3u32.to_le_bytes());
    assert!(parse_mem_write(&written, 3).is_ok());
    assert!(parse_mem_write(&written, 4).is_err());
}

#[test]
fn several_register_sets_in_one_reply() {
    let request = regs_read_many_request(7, 95, 0b11, 4);
    assert_eq!(request.len(), 32);
    assert_eq!(
        u32::from_le_bytes(request[4..8].try_into().unwrap()),
        REGS_ALL
    );
    assert_eq!(u32::from_le_bytes(request[16..20].try_into().unwrap()), 95);
    assert_eq!(
        u32::from_le_bytes(request[20..24].try_into().unwrap()),
        0b11
    );
    let part = |nt: u32, fill: u8, length: usize| {
        let mut part = Vec::new();
        part.extend(nt.to_le_bytes());
        part.extend((length as u32).to_le_bytes());
        part.extend([0u8; 8]);
        part.extend(vec![fill; length]);
        part
    };
    let mut reply = Vec::new();
    reply.extend(2u32.to_le_bytes());
    reply.extend([0u8; 12]);
    reply.extend(part(1, 0xaa, 216));
    reply.extend(part(2, 0xbb, 512));
    let blobs = parse_regs_many(&reply, &[1, 2]).unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!((blobs[0].nt_type, blobs[0].data.len()), (1, 216));
    assert_eq!((blobs[1].nt_type, blobs[1].data[0]), (2, 0xbb));
    // Wrong order, wrong count, a short or trailing byte: all refused.
    assert!(parse_regs_many(&reply, &[2, 1]).is_err());
    assert!(parse_regs_many(&reply, &[1]).is_err());
    assert!(parse_regs_many(&reply[..reply.len() - 1], &[1, 2]).is_err());
    let mut trailing = reply.clone();
    trailing.push(0);
    assert!(parse_regs_many(&trailing, &[1, 2]).is_err());
    for length in 0..reply.len().min(40) {
        assert!(parse_regs_many(&reply[..length], &[1, 2]).is_err());
    }
}

#[test]
fn thread_entries_carry_the_pending_signal() {
    let mut reply = Vec::new();
    reply.extend(1u32.to_le_bytes());
    reply.extend(1u32.to_le_bytes());
    reply.extend(95u32.to_le_bytes());
    reply.extend(2u32.to_le_bytes());
    reply.extend(6u32.to_le_bytes());
    reply.extend(11u32.to_le_bytes());
    reply.extend(0x4018c0u64.to_le_bytes());
    reply.extend([0u8; 8]);
    let threads = parse_threads(&reply).unwrap();
    assert_eq!(
        (threads[0].tid, threads[0].signal, threads[0].stopped),
        (95, 11, true)
    );
}
