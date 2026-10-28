// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::syscalls;

fn field(layout: &str, key: &str, data: &[u8]) -> FieldSummary {
    FieldSummary {
        arg: None,
        object_id: 1,
        key: key.into(),
        layout: if layout.is_empty() {
            String::new()
        } else {
            format!("linux-6.12.94/x86_64/{layout}")
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

fn line(layout: &str, data: &[u8]) -> String {
    decode(None, &field(layout, "arg1.data", data))
        .expect("decoded")
        .line()
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn a_signal_set_reads_as_names_and_a_mostly_full_one_as_its_complement() {
    let mask: u64 = (1 << 1) | (1 << 9) | (1 << 33);
    assert_eq!(
        line("sigset_t", &mask.to_le_bytes()),
        "[SIGINT SIGUSR1 SIG34]"
    );
    assert_eq!(line("sigset_t", &0u64.to_le_bytes()), "[]");
    let all_but = !((1u64 << 8) | (1 << 18));
    assert_eq!(
        line("sigset_t", &all_but.to_le_bytes()),
        "~[SIGKILL SIGSTOP]"
    );
    // rt_sigpending with a 4-byte size: signals 1-32 only.
    assert_eq!(line("sigset_t", &(1u32 << 16).to_le_bytes()), "[SIGCHLD]");
    assert!(decode(None, &field("sigset_t", "signal.mask", &[1, 2])).is_none());
}

#[test]
fn siginfo_takes_the_union_branch_the_signal_and_code_select() {
    let mut chld = [0u8; 128];
    put(&mut chld, 0, &17i32.to_le_bytes());
    put(&mut chld, 8, &1i32.to_le_bytes());
    put(&mut chld, 16, &321i32.to_le_bytes());
    put(&mut chld, 20, &1000u32.to_le_bytes());
    put(&mut chld, 24, &7i32.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &chld),
        "{si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=321, si_uid=1000, si_status=7, \
         si_utime=0, si_stime=0}"
    );
    // Killed: the status is a signal.
    put(&mut chld, 8, &2i32.to_le_bytes());
    put(&mut chld, 24, &9i32.to_le_bytes());
    assert!(line("siginfo_t", &chld).contains("si_code=CLD_KILLED"));
    assert!(line("siginfo_t", &chld).contains("si_status=SIGKILL"));

    let mut queued = [0u8; 128];
    put(&mut queued, 0, &10i32.to_le_bytes());
    put(&mut queued, 8, &(-1i32).to_le_bytes());
    put(&mut queued, 16, &55i32.to_le_bytes());
    put(&mut queued, 24, &0x2au64.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &queued),
        "{si_signo=SIGUSR1, si_code=SI_QUEUE, si_pid=55, si_uid=0, si_value=0x2a}"
    );

    let mut fault = [0u8; 128];
    put(&mut fault, 0, &11i32.to_le_bytes());
    put(&mut fault, 8, &1i32.to_le_bytes());
    put(&mut fault, 16, &0xdead_0000u64.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &fault),
        "{si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0xdead0000}"
    );
    put(&mut fault, 8, &4i32.to_le_bytes());
    put(&mut fault, 32, &3u32.to_le_bytes());
    assert!(
        line("siginfo_t", &fault).ends_with("si_code=SEGV_PKUERR, si_addr=0xdead0000, si_pkey=3}")
    );

    let mut timer = [0u8; 128];
    put(&mut timer, 0, &14i32.to_le_bytes());
    put(&mut timer, 4, &5i32.to_le_bytes());
    put(&mut timer, 8, &(-2i32).to_le_bytes());
    put(&mut timer, 16, &3i32.to_le_bytes());
    put(&mut timer, 20, &1i32.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &timer),
        "{si_signo=SIGALRM, si_errno=5, si_code=SI_TIMER, si_timerid=3, si_overrun=1, \
         si_value=NULL}"
    );

    let mut sys = [0u8; 128];
    put(&mut sys, 0, &31i32.to_le_bytes());
    put(&mut sys, 8, &1i32.to_le_bytes());
    put(&mut sys, 16, &0x40_1000u64.to_le_bytes());
    put(
        &mut sys,
        24,
        &(syscalls::number("getpid").unwrap() as i32).to_le_bytes(),
    );
    put(&mut sys, 28, &0xc000_003eu32.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &sys),
        "{si_signo=SIGSYS, si_code=SYS_SECCOMP, si_call_addr=0x401000, si_syscall=getpid, \
         si_arch=AUDIT_ARCH_X86_64}"
    );

    let mut poll = [0u8; 128];
    put(&mut poll, 0, &29i32.to_le_bytes());
    put(&mut poll, 8, &(-5i32).to_le_bytes());
    put(&mut poll, 16, &0x41i64.to_le_bytes());
    put(&mut poll, 24, &4i32.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &poll),
        "{si_signo=SIGIO, si_code=SI_SIGIO, si_band=POLLIN|POLLRDNORM, si_fd=4}"
    );

    // A user signal with a code no signal defines this far reads as poll
    // (the kernel's NSIGPOLL rule); a kernel-sent one as kill.
    let mut kill = [0u8; 128];
    put(&mut kill, 0, &15i32.to_le_bytes());
    put(&mut kill, 8, &0x80i32.to_le_bytes());
    assert_eq!(
        line("siginfo_t", &kill),
        "{si_signo=SIGTERM, si_code=SI_KERNEL, si_pid=0, si_uid=0}"
    );
    // Two entries of PTRACE_PEEKSIGINFO.
    let mut two = chld.to_vec();
    two.extend_from_slice(&kill);
    let decoded = decode(None, &field("siginfo_t[]", "arg3.siginfo", &two)).unwrap();
    assert_eq!(decoded.members.len(), 2);
    assert!(decoded.line().starts_with("[{si_signo=SIGCHLD"));
}

#[test]
fn sigevent_shows_what_its_notify_branch_uses() {
    let mut signal = [0u8; 64];
    put(&mut signal, 0, &0x2au64.to_le_bytes());
    put(&mut signal, 8, &10i32.to_le_bytes());
    assert_eq!(
        line("sigevent", &signal),
        "{sigev_notify=SIGEV_SIGNAL, sigev_signo=SIGUSR1, sigev_value=0x2a}"
    );
    put(&mut signal, 12, &4i32.to_le_bytes());
    put(&mut signal, 16, &77i32.to_le_bytes());
    assert_eq!(
        line("sigevent", &signal),
        "{sigev_notify=SIGEV_THREAD_ID, sigev_signo=SIGUSR1, sigev_value=0x2a, \
         sigev_notify_thread_id=77}"
    );
    let mut none = [0u8; 64];
    put(&mut none, 12, &1i32.to_le_bytes());
    assert_eq!(line("sigevent", &none), "{sigev_notify=SIGEV_NONE}");
    let mut thread = [0u8; 64];
    put(&mut thread, 8, &5i32.to_le_bytes());
    put(&mut thread, 12, &2i32.to_le_bytes());
    put(&mut thread, 0, &0x7000u64.to_le_bytes());
    assert_eq!(
        line("sigevent", &thread),
        "{sigev_notify=SIGEV_THREAD, sigev_signo=5, sigev_value=0x7000, \
         sigev_notify_function=NULL, sigev_notify_attributes=NULL}"
    );
}

#[test]
fn an_alternate_stack_and_pselect_pack_show_their_members() {
    let mut stack = [0u8; 24];
    put(&mut stack, 0, &0x7f00_0000u64.to_le_bytes());
    put(&mut stack, 8, &(2u32 | (1 << 31)).to_le_bytes());
    put(&mut stack, 16, &8192u64.to_le_bytes());
    assert_eq!(
        line("stack_t", &stack),
        "{ss_sp=0x7f000000, ss_flags=SS_DISABLE|SS_AUTODISARM, ss_size=8192}"
    );
    let mut pack = [0u8; 16];
    put(&mut pack, 8, &8u64.to_le_bytes());
    assert_eq!(line("sigset_argpack", &pack), "{ss=NULL, ss_len=8}");
}

#[test]
fn capabilities_combine_both_words_and_the_header_is_named_for_capget_only() {
    let mut data = [0u8; 24];
    put(&mut data, 0, &((1u32 << 21) | 1).to_le_bytes());
    put(&mut data, 4, &u32::MAX.to_le_bytes());
    put(&mut data, 16, &0x1ffu32.to_le_bytes());
    assert_eq!(
        line("cap_data[]", &data),
        "{effective=CAP_CHOWN|CAP_SYS_ADMIN, permitted=all, inheritable=0}"
    );
    // A set holding most capabilities names those it lacks.
    let mut most = [0u8; 24];
    put(&mut most, 0, &(!(1u32 << 22)).to_le_bytes());
    put(&mut most, 12, &0x1ffu32.to_le_bytes());
    assert_eq!(
        line("cap_data[]", &most),
        "{effective=all but CAP_SYS_BOOT, permitted=0, inheritable=0}"
    );
    let version = field("u32", "arg0.version", &0x2008_0522u32.to_le_bytes());
    let capget = Call {
        name: "capget",
        args: None,
    };
    assert_eq!(
        decode(Some(&capget), &version).unwrap().line(),
        "_LINUX_CAPABILITY_VERSION_3"
    );
    let odd = field("u32", "arg0.required_version", &7u32.to_le_bytes());
    assert_eq!(decode(Some(&capget), &odd).unwrap().line(), "0x7");
    let pid = field("pid_t", "arg0.pid", &(-1i32).to_le_bytes());
    assert_eq!(decode(Some(&capget), &pid).unwrap().line(), "-1");
    // Another call's u32 or pid_t is not decoded here.
    let other = Call {
        name: "clone3",
        args: None,
    };
    assert!(decode(Some(&other), &pid).is_none());
    assert!(decode(None, &version).is_none());
}

#[test]
fn ids_and_group_lists_are_numbers() {
    assert_eq!(line("uid_t", &1000u32.to_le_bytes()), "1000");
    let mut groups = Vec::new();
    for gid in [0u32, 4, 1000] {
        groups.extend_from_slice(&gid.to_le_bytes());
    }
    assert_eq!(line("gid_t[]", &groups), "[0, 4, 1000]");
    groups.push(1);
    assert_eq!(line("gid_t[]", &groups), "[0, 4, 1000, ...]");
}

fn dirent(wide: bool, ino: u64, kind: u8, name: &str) -> Vec<u8> {
    let header = if wide { 19 } else { 18 };
    let unpadded = header + name.len() + 1 + usize::from(!wide);
    let length = unpadded.div_ceil(8) * 8;
    let mut record = vec![0u8; length];
    put(&mut record, 0, &ino.to_le_bytes());
    put(&mut record, 8, &(length as u64).to_le_bytes());
    put(&mut record, 16, &(length as u16).to_le_bytes());
    if wide {
        record[18] = kind;
        put(&mut record, 19, name.as_bytes());
    } else {
        put(&mut record, 18, name.as_bytes());
        record[length - 1] = kind;
    }
    record
}

#[test]
fn directory_listings_read_as_their_entries() {
    for wide in [false, true] {
        let layout = if wide {
            "linux_dirent64[]"
        } else {
            "linux_dirent[]"
        };
        let mut data = dirent(wide, 2, 4, ".");
        data.extend(dirent(wide, 12, 8, "file.txt"));
        let decoded = decode(None, &field(layout, "arg1.data", &data)).unwrap();
        assert_eq!(decoded.members.len(), 2, "{layout}");
        assert!(!decoded.more);
        assert!(
            decoded.members[1]
                .1
                .contains("d_type=DT_REG, d_name=\"file.txt\"}")
        );
        assert!(decoded.members[0].1.starts_with("{d_ino=2, d_off="));
        // A record cut by the preview ends the list as more.
        let cut = &data[..data.len() - 3];
        let decoded = decode(None, &field(layout, "arg1.data", cut)).unwrap();
        assert_eq!(decoded.members.len(), 1);
        assert!(decoded.more);
    }
    // A record length that cannot hold a header stops decoding.
    let mut bad = dirent(true, 1, 8, "x");
    put(&mut bad, 16, &4u16.to_le_bytes());
    let decoded = decode(None, &field("linux_dirent64[]", "arg1.data", &bad)).unwrap();
    assert!(decoded.members.is_empty() && decoded.more);
}

#[test]
fn handles_rings_messages_and_tables_show_their_headers() {
    let mut header = [0u8; 8];
    put(&mut header, 0, &8u32.to_le_bytes());
    put(&mut header, 4, &1i32.to_le_bytes());
    assert_eq!(
        line("file_handle", &header),
        "{handle_bytes=8, handle_type=FILEID_INO32_GEN}"
    );

    let mut params = [0u8; 120];
    put(&mut params, 0, &16u32.to_le_bytes());
    put(&mut params, 4, &32u32.to_le_bytes());
    put(&mut params, 8, &(1u32 << 3).to_le_bytes());
    put(&mut params, 20, &0x3u32.to_le_bytes());
    put(&mut params, 44, &64u32.to_le_bytes());
    let text = line("io_uring_params", &params);
    assert!(text.starts_with(
        "{sq_entries=16, cq_entries=32, flags=IORING_SETUP_CQSIZE, sq_thread_cpu=0, \
         sq_thread_idle=0, features=IORING_FEAT_SINGLE_MMAP|IORING_FEAT_NODROP, wq_fd=0, \
         sq_off={head=0, tail=64,"
    ));
    assert!(
        decode(None, &field("io_uring_params", "arg1.params", &params))
            .unwrap()
            .lines()
            .iter()
            .any(|l| l.starts_with("cq_off = {head=0"))
    );

    let mut message = 3i64.to_le_bytes().to_vec();
    message.extend_from_slice(b"hi\0\x01");
    assert_eq!(line("msgbuf", &message), "{mtype=3, mtext=\"hi\\0\\x01\"}");

    let mut table = vec![0u8; 96 + 8];
    put(&mut table, 0, b"filter");
    put(&mut table, 32, &0b1110u32.to_le_bytes());
    put(&mut table, 36, &4u32.to_le_bytes());
    put(&mut table, 40, &656u32.to_le_bytes());
    put(&mut table, 48, &152u32.to_le_bytes());
    put(&mut table, 84, &4u32.to_le_bytes());
    let decoded = decode(None, &field("ipt_replace", "arg3.optval", &table)).unwrap();
    assert_eq!(
        decoded.line(),
        "{name=\"filter\", valid_hooks=INPUT|FORWARD|OUTPUT, num_entries=4, size=656, \
         hook_entry=[0, 152, 0, 0, 0], underflow=[0, 0, 0, 0, 0], num_counters=4, \
         counters=NULL, ...}"
    );
    let mut counters = vec![0u8; 40];
    put(&mut counters, 0, b"nat");
    put(&mut counters, 32, &2u32.to_le_bytes());
    assert_eq!(
        line("xt_counters_info", &counters),
        "{name=\"nat\", num_counters=2}"
    );
}

#[test]
fn ldt_entries_read_as_user_desc_and_descriptors() {
    let mut entry = [0u8; 16];
    put(&mut entry, 4, &0x1000u32.to_le_bytes());
    put(&mut entry, 8, &0xfffffu32.to_le_bytes());
    put(&mut entry, 12, &0b0001_0001u32.to_le_bytes());
    assert_eq!(
        line("user_desc", &entry),
        "{entry_number=0, base_addr=0x1000, limit=0xfffff, seg_32bit=1, contents=0, \
         read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=0, lm=0}"
    );
    // fill_ldt() of that entry: type 3 (data, writable, accessed), s=1,
    // dpl=3, p=1, d=1, g=1.
    let descriptor: u64 = 0xffff
        | (0x1000 << 16)
        | (0x3 << 40)
        | (1 << 44)
        | (3 << 45)
        | (1 << 47)
        | (0xf << 48)
        | (1 << 54)
        | (1 << 55);
    let mut data = descriptor.to_le_bytes().to_vec();
    data.extend_from_slice(&[0; 8]);
    assert_eq!(
        line("desc_struct[]", &data),
        "[{base=0x1000, limit=0xfffff, type=3, s=1, dpl=3, p=1, avl=0, l=0, d=1, g=1}, empty]"
    );
}

#[test]
fn bpf_attr_is_decoded_by_the_command_that_passed_it() {
    let mut attr = [0u8; 72];
    put(&mut attr, 0, &1u32.to_le_bytes());
    put(&mut attr, 4, &4u32.to_le_bytes());
    put(&mut attr, 8, &8u32.to_le_bytes());
    put(&mut attr, 12, &16u32.to_le_bytes());
    put(&mut attr, 28, b"counts");
    let map = Call {
        name: "bpf",
        args: Some([0, 0x1000, 72, 0, 0, 0]),
    };
    let decoded = decode(Some(&map), &field("bpf_attr", "arg1.attr", &attr)).unwrap();
    assert!(decoded.line().starts_with(
        "{map_type=BPF_MAP_TYPE_HASH, key_size=4, value_size=8, max_entries=16, map_flags=0x0, \
         inner_map_fd=0, numa_node=0, map_name=\"counts\", map_ifindex=0, btf_fd=0,"
    ));
    // The 72 bytes passed end with map_extra: the members after it are left out.
    assert_eq!(decoded.members.last().unwrap().0, "map_extra");

    let mut load = [0u8; 40];
    put(&mut load, 0, &2u32.to_le_bytes());
    put(&mut load, 4, &30u32.to_le_bytes());
    put(&mut load, 8, &0x5000u64.to_le_bytes());
    let prog = Call {
        name: "bpf",
        args: Some([5, 0, 40, 0, 0, 0]),
    };
    assert_eq!(
        decode(Some(&prog), &field("bpf_attr", "arg1.attr", &load))
            .unwrap()
            .line(),
        "{prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=30, insns=0x5000, license=NULL, \
         log_level=0, log_size=0, log_buf=NULL}"
    );
    assert_eq!(bpf_attr_member(5, &load, "insn_cnt"), Some(30));
    assert_eq!(bpf_attr_member(5, &load, "attach_bpf_fd"), None);
    assert_eq!(bpf_attr_member(8, &load, "attach_bpf_fd"), Some(30));

    // BPF_LINK_CREATE with BPF_TRACE_KPROBE_MULTI adds that branch.
    let mut link = [0u8; 48];
    put(&mut link, 0, &7u32.to_le_bytes());
    put(&mut link, 8, &42u32.to_le_bytes());
    put(&mut link, 20, &2u32.to_le_bytes());
    let link_call = Call {
        name: "bpf",
        args: Some([28, 0, 48, 0, 0, 0]),
    };
    let text = decode(Some(&link_call), &field("bpf_attr", "arg1.attr", &link))
        .unwrap()
        .line();
    assert!(text.starts_with(
        "{prog_fd=7, target_fd=0, attach_type=BPF_TRACE_KPROBE_MULTI, flags=0x0, \
         kprobe_multi.flags=0x0, kprobe_multi.cnt=2,"
    ));
    assert_eq!(bpf_attr_member(28, &link, "kprobe_multi.cnt"), Some(2));
    // Without the command, or with one 6.12.94 does not have, nothing.
    assert!(decode(None, &field("bpf_attr", "arg1.attr", &load)).is_none());
    let unknown = Call {
        name: "bpf",
        args: Some([0x7fff, 0, 16, 0, 0, 0]),
    };
    assert!(decode(Some(&unknown), &field("bpf_attr", "arg1.attr", &load)).is_none());
}

#[test]
fn bpf_member_offsets_agree_with_the_compiled_inventory_and_stay_inside_the_union() {
    let inventory: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/captured-layout-members.json"
    ))
    .unwrap();
    let attr = inventory["layouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|layout| layout["layout"] == "linux-6.12.94/x86_64/bpf_attr")
        .unwrap();
    // Every member the inventory qualifies for a command (its branch prefix
    // dropped: `query.attach_type`, `test.prog_fd`) is where ours is.
    let mut checked = 0;
    for member in attr["members"].as_array().unwrap() {
        let name = member["member"].as_str().unwrap();
        let name = name.split_once('.').map_or(name, |(_, rest)| rest);
        let offset = member["bit_offset"].as_u64().unwrap() / 8;
        for cmd in member["selector"]["values"].as_array().unwrap() {
            if let Some(ours) = bpf::member_offset(cmd.as_u64().unwrap(), name) {
                assert_eq!(ours as u64, offset, "{name} of command {cmd}");
                checked += 1;
            }
        }
    }
    assert!(checked > 150, "only {checked} members compared");
    for (cmd, members) in bpf::all_commands() {
        for member in members {
            assert!(
                member.1 + bpf::member_size(member) <= 152,
                "{} of {cmd}",
                member.0
            );
        }
    }
    for tail in bpf::ALL_LINK_TAILS {
        for member in *tail {
            assert!(member.1 + bpf::member_size(member) <= 152, "{}", member.0);
        }
    }
}

#[test]
fn partial_captures_and_other_layouts_are_not_guessed() {
    // Only bytes covered from offset 0 are decoded.
    let mut holed = field("stack_t", "arg0.stack", &[0; 24]);
    holed.ranges = vec![(8, 16)];
    assert!(decode(None, &holed).is_none());
    // A layout not decoded here.
    assert!(decode(None, &field("timespec", "arg0.data", &[0; 16])).is_none());
    assert!(decode(None, &field("", "arg1.buf", b"abc")).is_none());
    // More captured than the preview: marked.
    let mut long = field("gid_t[]", "arg1.data", &[0; 8]);
    long.captured_len = 400;
    long.logical_len = Some(400);
    assert!(decode(None, &long).unwrap().line().ends_with(", ...]"));
}

#[test]
fn long_lines_are_cut_and_detail_lines_list_each_member() {
    let mut data = Vec::new();
    for gid in 0u32..64 {
        data.extend_from_slice(&(gid * 100_000).to_le_bytes());
    }
    let decoded = decode(None, &field("gid_t[]", "arg1.data", &data)).unwrap();
    assert!(decoded.line().ends_with("..."));
    assert!(decoded.line().chars().count() <= LINE_MAX + 3);
    assert_eq!(decoded.lines().len(), 64);
    assert_eq!(decoded.lines()[1], "[1] 100000");
}
