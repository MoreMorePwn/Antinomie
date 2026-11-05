// SPDX-License-Identifier: GPL-3.0-only
//! Names for the kernel-interface structures (`perf_event_attr`, SysV IPC,
//! disk quotas, LSM contexts) and the context decoders of compat calls.
use super::*;

fn field_on(arch: &str, layout: &str, key: &str, data: &[u8]) -> FieldSummary {
    FieldSummary {
        arg: None,
        object_id: 1,
        key: key.into(),
        layout: format!("linux-6.12.94/{arch}/{layout}"),
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
) -> String {
    let call = Call {
        name,
        args: Some(args),
    };
    decode(Some(&call), &field_on(arch, layout, key, data))
        .unwrap_or_else(|| panic!("{name} {arch}/{layout} decoded"))
        .line()
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn a_perf_event_is_named_by_type_and_config() {
    for arch in ["x86_64", "aarch64"] {
        let mut attr = vec![0u8; 136];
        put(&mut attr, 4, &136u32.to_le_bytes());
        // PERF_COUNT_HW_INSTRUCTIONS, disabled, exclude_kernel, exclude_hv.
        put(&mut attr, 8, &1u64.to_le_bytes());
        put(&mut attr, 24, &((1u64 << 0) | (1 << 7)).to_le_bytes());
        attr[40] = 0b0110_0001;
        let line = line_on(arch, "perf_event_attr", &attr);
        assert!(
            line.starts_with(
                "{type=PERF_TYPE_HARDWARE, size=136, config=PERF_COUNT_HW_INSTRUCTIONS"
            ),
            "{line}"
        );
        assert!(
            line.contains("sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CPU"),
            "{line}"
        );
        assert!(
            line.contains("flags=disabled|exclude_kernel|exclude_hv"),
            "{line}"
        );
        assert!(!line.contains("disabled=1"), "{line}");
        // A software event, a cache event, a tracepoint, a raw event.
        put(&mut attr, 0, &1u32.to_le_bytes());
        put(&mut attr, 8, &9u64.to_le_bytes());
        assert!(line_on(arch, "perf_event_attr", &attr).contains("config=PERF_COUNT_SW_DUMMY"));
        put(&mut attr, 0, &3u32.to_le_bytes());
        put(&mut attr, 8, &0x1_0000u64.to_le_bytes());
        assert!(
            line_on(arch, "perf_event_attr", &attr)
                .contains("config=PERF_COUNT_HW_CACHE_L1D|OP_READ|RESULT_MISS")
        );
        put(&mut attr, 0, &2u32.to_le_bytes());
        put(&mut attr, 8, &321u64.to_le_bytes());
        assert!(line_on(arch, "perf_event_attr", &attr).contains("config=tracepoint 321"));
        put(&mut attr, 0, &4u32.to_le_bytes());
        put(&mut attr, 8, &0x1c2u64.to_le_bytes());
        assert!(line_on(arch, "perf_event_attr", &attr).contains("config=0x1c2"));
    }
}

#[test]
fn sysv_ipc_times_read_as_dates() {
    for arch in ["x86_64", "aarch64"] {
        let mut queue = vec![0u8; 120];
        put(&mut queue, 20, &0o600u32.to_le_bytes());
        put(&mut queue, 48, &1_700_000_000i64.to_le_bytes());
        put(&mut queue, 80, &3u64.to_le_bytes());
        let line = line_on(arch, "msqid64_ds", &queue);
        assert!(line.contains("mode=0600"), "{line}");
        assert!(line.contains("msg_stime=2023-11-14 22:13:20 UTC"), "{line}");
        assert!(line.contains("msg_qnum=3"), "{line}");
        // A time never set stays 0.
        assert!(line.contains("msg_rtime=0"), "{line}");
    }
}

#[test]
fn quota_blocks_name_their_valid_bits_and_times() {
    for arch in ["x86_64", "aarch64"] {
        let mut block = vec![0u8; 72];
        put(&mut block, 48, &1_700_000_000u64.to_le_bytes());
        put(&mut block, 64, &0x3u32.to_le_bytes());
        let line = line_on(arch, "if_dqblk", &block);
        assert!(line.contains("dqb_valid=QIF_BLIMITS|QIF_SPACE"), "{line}");
        assert!(line.contains("dqb_btime=2023-11-14 22:13:20 UTC"), "{line}");
        let mut info = vec![0u8; 24];
        put(&mut info, 16, &1u32.to_le_bytes());
        put(&mut info, 20, &4u32.to_le_bytes());
        let line = line_on(arch, "if_dqinfo", &info);
        assert!(line.contains("dqi_flags=DQF_ROOT_SQUASH"), "{line}");
        assert!(line.contains("dqi_valid=IIF_FLAGS"), "{line}");
        let mut xfs = vec![0u8; 112];
        xfs[1] = 4;
        put(&mut xfs, 2, &0x8u16.to_le_bytes());
        let line = line_on(arch, "fs_disk_quota", &xfs);
        assert!(line.contains("d_flags=FS_GROUP_QUOTA"), "{line}");
        assert!(line.contains("d_fieldmask=FS_DQ_BHARD"), "{line}");
    }
}

#[test]
fn an_lsm_context_names_the_module_and_shows_the_label() {
    let mut ctx = vec![0u8; 32];
    put(&mut ctx, 0, &101u64.to_le_bytes());
    put(&mut ctx, 8, &1u64.to_le_bytes());
    put(&mut ctx, 16, &44u64.to_le_bytes());
    put(&mut ctx, 24, &11u64.to_le_bytes());
    ctx.extend(b"unconfined\0");
    for arch in ["x86_64", "aarch64"] {
        let line = line_on(arch, "lsm_ctx", &ctx);
        assert!(line.contains("id=LSM_ID_SELINUX"), "{line}");
        assert!(line.contains("flags=LSM_FLAG_SINGLE"), "{line}");
        assert!(line.ends_with("ctx=\"unconfined\"}"), "{line}");
    }
}

#[test]
fn compat_wait_status_and_socket_options_read_by_call() {
    // wait4 and i386's waitpid store the same 32-bit status.
    for (arch, call) in [("x86", "waitpid"), ("arm", "wait4"), ("x86", "wait4")] {
        let line = with_call(
            call,
            [0; 6],
            arch,
            "wait_status",
            "arg1.status",
            &[0, 3, 0, 0],
        );
        assert_eq!(line, "exited 3");
        let killed = with_call(
            call,
            [0; 6],
            arch,
            "wait_status",
            "arg1.status",
            &[0x8b, 0, 0, 0],
        );
        assert_eq!(killed, "killed by SIGSEGV (core dumped)");
    }
    // SO_REUSEADDR is a switch, SO_TYPE a socket type, on both compat ABIs.
    for arch in ["x86", "arm"] {
        let args = [3, 1, 2, 0x1000, 4, 0];
        assert_eq!(
            with_call(
                "setsockopt",
                args,
                arch,
                "int",
                "arg3.optval",
                &1u32.to_le_bytes()
            ),
            "on"
        );
        let args = [3, 1, 3, 0x1000, 0x1004, 0];
        assert_eq!(
            with_call(
                "getsockopt",
                args,
                arch,
                "int",
                "arg3.optval",
                &2u32.to_le_bytes()
            ),
            "SOCK_DGRAM"
        );
    }
}

#[test]
fn compat_pipes_and_sets_have_their_own_words() {
    for arch in ["x86", "arm"] {
        let mut fds = [0u8; 8];
        put(&mut fds, 0, &3u32.to_le_bytes());
        put(&mut fds, 4, &4u32.to_le_bytes());
        assert_eq!(
            with_call("pipe2", [0; 6], arch, "int[2]", "arg0.fildes", &fds),
            "{read=3, write=4}"
        );
    }
    // mbind's node mask on a 32-bit program.
    assert_eq!(
        with_call(
            "mbind",
            [0, 0, 2, 0, 33, 0],
            "arm",
            "unsigned_long[]",
            "arg3.nmask",
            &[0b101, 0, 0, 0, 0b1, 0, 0, 0]
        ),
        "0,2,32"
    );
}

#[test]
fn socket_addresses_decode_by_family() {
    let mut netlink = vec![16, 0, 0, 0];
    netlink.extend(0u32.to_le_bytes());
    netlink.extend(0x11u32.to_le_bytes());
    assert_eq!(
        sockaddr(&netlink, None).as_deref(),
        Some("netlink:pid=0,groups=0x11")
    );
    assert_eq!(
        sockaddr(&netlink, Some(0)).as_deref(),
        Some("netlink:NETLINK_ROUTE:pid=0,groups=RTMGRP_LINK|RTMGRP_IPV4_IFADDR")
    );
    assert_eq!(
        sockaddr(&netlink, Some(15)).as_deref(),
        Some("netlink:NETLINK_KOBJECT_UEVENT:pid=0,groups=0x11")
    );
    let mut packet = vec![17, 0, 0x00, 0x03];
    packet.extend(2i32.to_le_bytes());
    packet.extend([0, 0, 0, 0]);
    assert_eq!(
        sockaddr(&packet, None).as_deref(),
        Some("packet:proto=ETH_P_ALL,ifindex=2")
    );
    let mut sent = vec![17, 0, 0x08, 0x00];
    sent.extend(3i32.to_le_bytes());
    sent.extend([1, 0, 1, 6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]);
    assert_eq!(
        sockaddr(&sent, None).as_deref(),
        Some(
            "packet:proto=ETH_P_IP,ifindex=3,hatype=ARPHRD_ETHER,pkttype=PACKET_BROADCAST,mac=ff:ff:ff:ff:ff:ff"
        )
    );
    let mut vsock = vec![40, 0, 0, 0];
    vsock.extend(1234u32.to_le_bytes());
    vsock.extend(2u32.to_le_bytes());
    assert_eq!(
        sockaddr(&vsock, None).as_deref(),
        Some("vsock:VMADDR_CID_HOST:1234")
    );
    let mut alg = vec![38, 0];
    alg.extend(b"hash\0\0\0\0\0\0\0\0\0\0");
    alg.extend([0; 8]);
    alg.extend(b"sha256\0");
    alg.resize(2 + 14 + 8 + 64, 0);
    assert_eq!(sockaddr(&alg, None).as_deref(), Some("alg:hash/sha256"));
    assert_eq!(sockaddr(&[0, 0, 0, 0], None).as_deref(), Some("AF_UNSPEC"));
    assert_eq!(sockaddr(&[9, 0, 0, 0], None), None);
}
