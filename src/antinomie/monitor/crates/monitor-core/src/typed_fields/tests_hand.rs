// SPDX-License-Identifier: GPL-3.0-only
//! The hand-written readers of layouts the inventory does not describe: AIO,
//! io_uring, signal frames and register sets, bitmaps, and the context
//! decoders (select sets, affinity, regsets) on native and compat ABIs.
use super::*;

fn field_on(arch: &str, layout: &str, key: &str, data: &[u8]) -> FieldSummary {
    FieldSummary {
        arg: None,
        object_id: 1,
        key: key.into(),
        layout: if layout.is_empty() {
            String::new()
        } else {
            format!("linux-6.12.94/{arch}/{layout}")
        },
        logical_len: Some(data.len() as u64),
        captured_len: data.len() as u64,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: data.to_vec(),
        raw_path: None,
        ranges: vec![(0, data.len() as u64)],
        recapture: None,
        encoding: None,
    }
}

fn line_on(arch: &str, layout: &str, data: &[u8]) -> String {
    decode(None, &field_on(arch, layout, "arg1.data", data))
        .unwrap_or_else(|| panic!("{arch}/{layout} decoded"))
        .line()
}

fn with_call(
    name: &str,
    args: [u64; 6],
    arch: &str,
    layout: &str,
    key: &str,
    data: &[u8],
) -> Option<Decoded> {
    let call = Call {
        name,
        args: Some(args),
    };
    decode(Some(&call), &field_on(arch, layout, key, data))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

const ALL: [&str; 4] = ["x86_64", "aarch64", "x86", "arm"];

#[test]
fn an_iocb_reads_by_its_members_on_every_abi() {
    let mut iocb = [0u8; 64];
    put(&mut iocb, 0, &0xdead_u64.to_le_bytes());
    put(&mut iocb, 12, &0x2u32.to_le_bytes());
    put(&mut iocb, 16, &8u16.to_le_bytes());
    put(&mut iocb, 20, &5u32.to_le_bytes());
    put(&mut iocb, 24, &0x7000_u64.to_le_bytes());
    put(&mut iocb, 32, &3u64.to_le_bytes());
    put(&mut iocb, 40, &4096i64.to_le_bytes());
    for arch in ALL {
        assert_eq!(
            line_on(arch, "iocb", &iocb),
            "{aio_data=0xdead, aio_key=0, aio_rw_flags=RWF_DSYNC, \
             aio_lio_opcode=IOCB_CMD_PWRITEV, aio_reqprio=0, aio_fildes=5, \
             aio_buf=0x7000, aio_nbytes=3, aio_offset=4096, aio_flags=0, aio_resfd=0}"
        );
    }
}

#[test]
fn io_events_list_their_results() {
    let mut events = [0u8; 64];
    put(&mut events, 0, &7u64.to_le_bytes());
    put(&mut events, 8, &0x1000_u64.to_le_bytes());
    put(&mut events, 16, &(-5i64).to_le_bytes());
    put(&mut events, 32, &8u64.to_le_bytes());
    put(&mut events, 48, &512i64.to_le_bytes());
    for arch in ALL {
        assert_eq!(
            line_on(arch, "io_event[]", &events),
            "[{data=0x7, obj=0x1000, res=-5, res2=0}, {data=0x8, obj=NULL, res=512, res2=0}]"
        );
    }
    assert_eq!(
        line_on("arm", "io_event", &events[..32]),
        "{data=0x7, obj=0x1000, res=-5, res2=0}"
    );
}

#[test]
fn the_aio_sigset_and_pointer_arrays_follow_the_pointer_width() {
    let mut wide = [0u8; 16];
    put(&mut wide, 0, &0x7ffd_0000u64.to_le_bytes());
    put(&mut wide, 8, &8u64.to_le_bytes());
    assert_eq!(
        line_on("x86_64", "__aio_sigset", &wide),
        "{sigmask=0x7ffd0000, sigsetsize=8}"
    );
    let mut narrow = [0u8; 8];
    put(&mut narrow, 0, &0xbfff_0000u32.to_le_bytes());
    put(&mut narrow, 4, &8u32.to_le_bytes());
    assert_eq!(
        line_on("x86", "__aio_sigset", &narrow),
        "{sigmask=0xbfff0000, sigsetsize=8}"
    );
    assert_eq!(
        line_on("aarch64", "pointer[]", &[wide, [0; 16]].concat()[..24]),
        "[0x7ffd0000, 0x8, NULL]"
    );
    assert_eq!(line_on("arm", "pointer[]", &narrow), "[0xbfff0000, 0x8]");
    assert_eq!(line_on("x86_64", "pointer", &wide[..8]), "0x7ffd0000");
}

#[test]
fn a_cpu_mask_reads_as_a_list() {
    let mut mask = [0u8; 16];
    mask[0] = 0b0100_1111;
    assert_eq!(line_on("x86_64", "cpumask", &mask), "0-3,6");
    mask[1] = 0b1;
    mask[0] = 0xff;
    assert_eq!(line_on("aarch64", "cpumask", &mask), "0-8");
    assert_eq!(line_on("arm", "cpumask", &[0; 4]), "none");
    // sched_setaffinity's mask, native and compat words.
    let affinity = with_call(
        "sched_setaffinity",
        [0, 8, 0, 0, 0, 0],
        "x86_64",
        "unsigned_long[]",
        "arg2.user_mask_ptr",
        &[0b0100_1111, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    assert_eq!(affinity.line(), "0-3,6");
    let compat = with_call(
        "sched_getaffinity",
        [0, 8, 0, 0, 0, 0],
        "arm",
        "u32[]",
        "arg2.user_mask_ptr",
        &[0b11, 0, 0, 0, 0b1, 0, 0, 0],
    )
    .unwrap();
    assert_eq!(compat.line(), "0-1,32");
}

#[test]
fn a_submission_entry_reads_by_opcode_and_flags() {
    let mut sqe = [0u8; 64];
    sqe[0] = 18;
    sqe[1] = 0b101;
    put(&mut sqe, 4, &(-100i32).to_le_bytes());
    put(&mut sqe, 16, &0x7ffe_1000_u64.to_le_bytes());
    put(&mut sqe, 24, &0o644u32.to_le_bytes());
    put(&mut sqe, 32, &0x42_u64.to_le_bytes());
    for arch in ALL {
        assert_eq!(
            line_on(arch, "io_uring_sqe", &sqe),
            "{opcode=IORING_OP_OPENAT, flags=IOSQE_FIXED_FILE|IOSQE_IO_LINK, ioprio=0, \
             fd=AT_FDCWD, off=0x0, addr=0x7ffe1000, len=420, op_flags=0x0, user_data=0x42, \
             buf_index=0, personality=0, splice_fd_in=0, addr3=0x0}"
        );
    }
    let two = [sqe, [0u8; 64]].concat();
    let list = decode(
        None,
        &field_on("aarch64", "io_uring_sqe[]", "arg1.sqes", &two),
    )
    .unwrap();
    assert_eq!(list.members.len(), 2);
    assert!(list.members[1].1.starts_with("{opcode=IORING_OP_NOP"));
}

#[test]
fn the_rings_the_probe_and_the_buffer_ring_read_by_member() {
    let mut rings = vec![0u8; 256];
    put(&mut rings, 64, &9u32.to_le_bytes());
    put(&mut rings, 192, &3u32.to_le_bytes());
    let decoded = decode(
        None,
        &field_on("x86_64", "io_rings", "arg1.user_rings", &rings),
    )
    .unwrap();
    assert_eq!(decoded.members[0].0, "sq");
    assert_eq!(decoded.members[0].1, "{head=0, tail=9}");
    assert_eq!(decoded.members[1].1, "{head=0, tail=3}");
    // The probe: two ops, one supported.
    let mut probe = vec![0u8; 16 + 16];
    probe[0] = 57;
    probe[1] = 2;
    probe[16] = 0;
    probe[18] = 1;
    probe[24] = 1;
    assert_eq!(
        line_on("aarch64", "io_uring_probe", &probe),
        "{last_op=IORING_OP_LISTEN, ops_len=2, supported=[IORING_OP_NOP]}"
    );
    let mut arg = [0u8; 24];
    put(&mut arg, 8, &8u32.to_le_bytes());
    put(&mut arg, 16, &0x6000_u64.to_le_bytes());
    assert_eq!(
        line_on("x86_64", "io_uring_getevents_arg", &arg),
        "{sigmask=NULL, sigmask_sz=8, min_wait_usec=0, ts=0x6000}"
    );
    let mut buffers = [0u8; 32];
    put(&mut buffers, 0, &0x9000_u64.to_le_bytes());
    put(&mut buffers, 8, &4096u32.to_le_bytes());
    put(&mut buffers, 12, &1u16.to_le_bytes());
    assert_eq!(
        line_on("aarch64", "io_uring_buf[]", &buffers),
        "[{addr=0x9000, len=4096, bid=1}, {addr=NULL, len=0, bid=0}]"
    );
}

#[test]
fn an_x86_signal_frame_names_where_the_handler_returns() {
    let mut frame = vec![0u8; 256];
    put(&mut frame, 0, &0x7f00_1000_u64.to_le_bytes());
    put(&mut frame, 8, &0x7_u64.to_le_bytes());
    put(&mut frame, 24, &0x7f00_8000_u64.to_le_bytes());
    put(&mut frame, 40, &0x4000_u64.to_le_bytes());
    put(&mut frame, 176, &0x401234_u64.to_le_bytes());
    put(&mut frame, 168, &0x7ffd_f000_u64.to_le_bytes());
    put(&mut frame, 184, &0x246_u64.to_le_bytes());
    put(&mut frame, 192, &0x33u16.to_le_bytes());
    let decoded = decode(
        None,
        &field_on("x86_64", "rt_sigframe", "context.rt_sigframe", &frame),
    )
    .unwrap();
    let line = decoded.full_line();
    assert!(
        line.starts_with("{pretcode=0x7f001000, uc={uc_flags=0x7, uc_link=NULL"),
        "{line}"
    );
    assert!(
        line.contains("uc_stack={ss_sp=0x7f008000, ss_flags=0, ss_size=16384}"),
        "{line}"
    );
    assert!(line.contains("rip=0x401234"), "{line}");
    assert!(line.contains("eflags=PF|ZF|IF"), "{line}");
    assert!(line.contains("cs=0x33"), "{line}");
    assert!(decoded.more, "the signal mask lies past the preview");
    // The whole 440-byte frame: the mask and the siginfo are read too.
    let mut whole = frame.clone();
    whole.resize(440, 0);
    put(&mut whole, 304, &(1u64 << 9).to_le_bytes());
    put(&mut whole, 312, &11i32.to_le_bytes());
    let decoded = decode(
        None,
        &field_on("x86_64", "rt_sigframe", "context.rt_sigframe", &whole),
    )
    .unwrap();
    let line = decoded.full_line();
    assert!(line.contains("uc_sigmask=[SIGUSR1]"), "{line}");
    assert!(line.contains("info={"), "{line}");
    assert!(!decoded.more, "{line}");
}

#[test]
fn an_aarch64_signal_frame_leads_with_siginfo() {
    let mut frame = vec![0u8; 256];
    put(&mut frame, 0, &11i32.to_le_bytes());
    put(&mut frame, 8, &1i32.to_le_bytes());
    put(&mut frame, 128, &0x2_u64.to_le_bytes());
    put(&mut frame, 168, &(1u64 << 1).to_le_bytes());
    let decoded = decode(
        None,
        &field_on("aarch64", "rt_sigframe", "context.rt_sigframe", &frame),
    )
    .unwrap();
    let line = decoded.full_line();
    assert!(line.starts_with("{info={"), "{line}");
    assert!(line.contains("SIGSEGV"), "{line}");
    assert!(line.contains("uc={uc_flags=0x2"), "{line}");
    assert!(line.contains("uc_sigmask=[SIGINT]"), "{line}");
}

#[test]
fn floating_point_state_is_a_summary() {
    let mut fx = vec![0u8; 512];
    put(&mut fx, 0, &0x37f_u16.to_le_bytes());
    put(&mut fx, 24, &0x1f80_u32.to_le_bytes());
    fx[160] = 1;
    fx[176] = 2;
    put(&mut fx, 464, &0x4650_5853_u32.to_le_bytes());
    put(&mut fx, 468, &832u32.to_le_bytes());
    put(&mut fx, 472, &7u64.to_le_bytes());
    put(&mut fx, 480, &832u32.to_le_bytes());
    let line = line_on("x86_64", "fxregs_state", &fx);
    assert!(line.contains("cwd=0x37f"), "{line}");
    assert!(line.contains("mxcsr=0x1f80"), "{line}");
    assert!(line.contains("st_registers_in_use=0"), "{line}");
    assert!(line.contains("xmm_registers_in_use=2"), "{line}");
    assert!(
        line.contains("sw_reserved={magic1=FP_XSTATE_MAGIC1, extended_size=832, xfeatures=X87|SSE|YMM, xstate_size=832}"),
        "{line}"
    );
    let mut xsave = vec![0u8; 320];
    put(&mut xsave, 0, &7u64.to_le_bytes());
    xsave[64 + 16] = 9;
    assert_eq!(
        line_on("x86_64", "xstate", &xsave),
        "{xfeatures=X87|SSE|YMM, xcomp_bv=0x0, ymm_hi128_in_use=1, bytes=320}"
    );
    let mut regs = [0u8; 24];
    put(&mut regs, 8, &0x401000_u64.to_le_bytes());
    assert_eq!(
        line_on("x86_64", "uretprobe_regs", &regs),
        "{r11=0x0, rcx=0x401000, rax=0x0}"
    );
}

#[test]
fn register_sets_are_told_by_note_and_length() {
    // aarch64 NT_PRSTATUS: x0-x30 then sp (the preview ends at 256).
    let mut regs = vec![0u8; 256];
    put(&mut regs, 0, &5u64.to_le_bytes());
    put(&mut regs, 240, &0x1e_u64.to_le_bytes());
    put(&mut regs, 248, &0x7ffd_0000_u64.to_le_bytes());
    let mut field = field_on("", "", "arg3.iovec.data", &regs);
    field.logical_len = Some(272);
    field.arg = Some(3);
    let call = Call {
        name: "ptrace",
        args: Some([0x4204, 1, 1, 0x7ffe_0000, 0, 0]),
    };
    let decoded = decode(Some(&call), &field).unwrap();
    let line = decoded.full_line();
    assert!(line.starts_with("{regs={x0=0x5, x1=0x0"), "{line}");
    assert!(line.contains("x30=0x1e"), "{line}");
    assert!(line.contains("sp=0x7ffd0000"), "{line}");
    assert!(decoded.more, "pc and pstate lie past the preview");
    // The whole set, with its processor state.
    let mut whole = regs.clone();
    whole.extend([0; 16]);
    put(&mut whole, 256, &0x4000_1000_u64.to_le_bytes());
    put(&mut whole, 264, &(0x6000_0000u64).to_le_bytes());
    let mut field = field_on("", "", "arg3.iovec.data", &whole);
    field.arg = Some(3);
    field.logical_len = Some(272);
    let line = decode(Some(&call), &field).unwrap().full_line();
    assert!(line.contains("pc=0x40001000, pstate=EL0t Z|C"), "{line}");
    // An AArch32 task's set is 72 bytes: r0-r12, sp, lr, pc, cpsr, orig_r0.
    let mut arm = vec![0u8; 72];
    put(&mut arm, 0, &3u32.to_le_bytes());
    put(&mut arm, 60, &0x10000_u32.to_le_bytes());
    put(&mut arm, 64, &0x6000_0030_u32.to_le_bytes());
    let mut field = field_on("", "", "arg3.iovec.data", &arm);
    field.arg = Some(3);
    let line = decode(Some(&call), &field).unwrap().full_line();
    assert!(line.contains("r0=0x3"), "{line}");
    assert!(line.contains("pc=0x10000"), "{line}");
    assert!(line.contains("cpsr=USR Z|C|T"), "{line}");
    // SETREGSET reads the same; another note is left to the bytes.
    let other = Call {
        name: "ptrace",
        args: Some([0x4205, 1, 99, 0x7ffe_0000, 0, 0]),
    };
    assert!(decode(Some(&other), &field).is_none());
}

#[test]
fn select_sets_read_by_the_word_size_of_the_program() {
    let native = with_call(
        "select",
        [8, 0, 0, 0, 0, 0],
        "x86_64",
        "unsigned_long[]",
        "arg1.fdset",
        &[0b0010_1000, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    assert_eq!(native.line(), "[fd 3, fd 5]");
    // i386 _newselect: 32-bit words, 40 descriptors.
    let compat = with_call(
        "_newselect",
        [40, 0, 0, 0, 0, 0],
        "x86",
        "u32[]",
        "arg1.fdset",
        &[0b1, 0, 0, 0, 0b10, 0, 0, 0],
    )
    .unwrap();
    assert_eq!(compat.line(), "[fd 0, fd 33]");
}
