// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! eBPF instruction text shared by the BPF viewer and the `bpf_insn[]` record
//! decoder: one instruction as an assembly-like line, and the helper registry
//! of the pinned Linux 6.12.94 UAPI. Pure functions over decoded fields.
pub fn ebpf_landing_wide(index: usize, offset: i32, len: usize) -> String {
    let target = index as i64 + i64::from(offset) + 1;
    if target >= 0 && target < len as i64 {
        format!("insn {target}")
    } else {
        "unavailable target outside captured image".into()
    }
}

pub fn mnemonic(op: u8, dst: u8, src: u8, off: i16, imm: i32, index: usize, len: usize) -> String {
    let class = op & 0x07;
    let source = if op & 0x08 == 0 {
        format!("r{dst}")
    } else {
        format!("r{src}")
    };
    match class {
        0x04 | 0x07 => {
            let width = if class == 0x07 { "64" } else { "32" };
            let operation = match (op >> 4) & 0x0f {
                0x0 => "add",
                0x1 => "sub",
                0x2 => "mul",
                0x3 => "div",
                0x4 => "or",
                0x5 => "and",
                0x6 => "lsh",
                0x7 => "rsh",
                0x8 => "neg",
                0x9 => "mod",
                0xa => "xor",
                0xb => "mov",
                0xc => "arsh",
                0xd => "end",
                _ => return format!("unresolved alu opcode {op:#04x}, r{dst}, r{src}, {imm}"),
            };
            if operation == "end" {
                format!(
                    "endian r{dst}, {}{imm}",
                    if op & 8 == 0 { "le" } else { "be" }
                )
            } else if operation == "neg" {
                format!("{operation}{width} r{dst}")
            } else if op & 0x08 == 0 {
                format!("{operation}{width} r{dst}, {imm}")
            } else {
                format!("{operation}{width} r{dst}, {source}")
            }
        }
        0x05 | 0x06 => {
            let operation = match (op >> 4) & 0x0f {
                0x0 => "ja",
                0x1 => "jeq",
                0x2 => "jgt",
                0x3 => "jge",
                0x4 => "jset",
                0x5 => "jne",
                0x6 => "jsgt",
                0x7 => "jsge",
                0x8 => "call",
                0x9 => "exit",
                0xa => "jlt",
                0xb => "jle",
                0xc => "jslt",
                0xd => "jsle",
                _ => "jmp",
            };
            if operation == "exit" {
                "exit".into()
            } else if operation == "call" {
                match src {
                    0 => format!("call {}", helper(imm)),
                    1 => format!("call local {}", ebpf_landing_wide(index, imm, len)),
                    2 => format!("call unresolved BTF kernel function ID {imm}"),
                    _ => format!("call unresolved pseudo source {src}, immediate {imm}"),
                }
            } else if operation == "ja" {
                if class == 6 {
                    format!("ja32 {imm:+} -> {}", ebpf_landing_wide(index, imm, len))
                } else {
                    format!("ja {off:+} {}", ebpf_landing(index, off, len))
                }
            } else if op & 0x08 == 0 {
                format!(
                    "{operation} r{dst}, {imm}, {off:+} {}",
                    ebpf_landing(index, off, len)
                )
            } else {
                format!(
                    "{operation} r{dst}, r{src}, {off:+} {}",
                    ebpf_landing(index, off, len)
                )
            }
        }
        0x00..=0x03 => {
            let size = match op & 0x18 {
                0x00 => "w",
                0x08 => "h",
                0x10 => "b",
                _ => "dw",
            };
            match (class, op & 0xe0) {
                (0, 0x20) => format!("ldabs{size} r0, packet[{imm:+}]"),
                (0, 0x40) => format!("ldind{size} r0, packet[r{src}{imm:+}]"),
                (1, 0x60) => format!("ldx{size} r{dst}, [r{src}{off:+}]"),
                (2, 0x60) => format!("st{size} [r{dst}{off:+}], {imm}"),
                (3, 0x60) => format!("stx{size} [r{dst}{off:+}], r{src}"),
                (3, 0xc0) => format!(
                    "atomic{size} [r{dst}{off:+}], r{src}, operation={imm:#x}; fetch/cmpxchg semantics from opcode"
                ),
                _ => format!("unresolved memory opcode {op:#04x}, r{dst}, r{src}, {off}, {imm}"),
            }
        }
        _ => format!("op {op:#04x} r{dst}, r{src}, {off}, {imm}"),
    }
}

/// The eBPF offset is relative to the next instruction: `index + offset + 1`.
pub fn ebpf_landing(index: usize, off: i16, len: usize) -> String {
    let target = index as i64 + i64::from(off) + 1;
    if target >= 0 && target < len as i64 {
        format!("-> insn {target}")
    } else {
        "-> outside".into()
    }
}

// Helper names/IDs follow the pinned Linux 6.12.94 UAPI bpf_func_id registry.
pub fn helper(id: i32) -> String {
    let name = match id {
        0 => "unspec",
        1 => "map_lookup_elem",
        2 => "map_update_elem",
        3 => "map_delete_elem",
        4 => "probe_read",
        5 => "ktime_get_ns",
        6 => "trace_printk",
        7 => "get_prandom_u32",
        8 => "get_smp_processor_id",
        9 => "skb_store_bytes",
        10 => "l3_csum_replace",
        11 => "l4_csum_replace",
        12 => "tail_call",
        13 => "clone_redirect",
        14 => "get_current_pid_tgid",
        15 => "get_current_uid_gid",
        16 => "get_current_comm",
        17 => "get_cgroup_classid",
        18 => "skb_vlan_push",
        19 => "skb_vlan_pop",
        20 => "skb_get_tunnel_key",
        21 => "skb_set_tunnel_key",
        22 => "perf_event_read",
        23 => "redirect",
        24 => "get_route_realm",
        25 => "perf_event_output",
        26 => "skb_load_bytes",
        27 => "get_stackid",
        28 => "csum_diff",
        29 => "skb_get_tunnel_opt",
        30 => "skb_set_tunnel_opt",
        31 => "skb_change_proto",
        32 => "skb_change_type",
        33 => "skb_under_cgroup",
        34 => "get_hash_recalc",
        35 => "get_current_task",
        36 => "probe_write_user",
        37 => "current_task_under_cgroup",
        38 => "skb_change_tail",
        39 => "skb_pull_data",
        40 => "csum_update",
        41 => "set_hash_invalid",
        42 => "get_numa_node_id",
        43 => "skb_change_head",
        44 => "xdp_adjust_head",
        45 => "probe_read_str",
        46 => "get_socket_cookie",
        47 => "get_socket_uid",
        48 => "set_hash",
        49 => "setsockopt",
        50 => "skb_adjust_room",
        51 => "redirect_map",
        52 => "sk_redirect_map",
        53 => "sock_map_update",
        54 => "xdp_adjust_meta",
        55 => "perf_event_read_value",
        56 => "perf_prog_read_value",
        57 => "getsockopt",
        58 => "override_return",
        59 => "sock_ops_cb_flags_set",
        60 => "msg_redirect_map",
        61 => "msg_apply_bytes",
        62 => "msg_cork_bytes",
        63 => "msg_pull_data",
        64 => "bind",
        65 => "xdp_adjust_tail",
        66 => "skb_get_xfrm_state",
        67 => "get_stack",
        68 => "skb_load_bytes_relative",
        69 => "fib_lookup",
        70 => "sock_hash_update",
        71 => "msg_redirect_hash",
        72 => "sk_redirect_hash",
        73 => "lwt_push_encap",
        74 => "lwt_seg6_store_bytes",
        75 => "lwt_seg6_adjust_srh",
        76 => "lwt_seg6_action",
        77 => "rc_repeat",
        78 => "rc_keydown",
        79 => "skb_cgroup_id",
        80 => "get_current_cgroup_id",
        81 => "get_local_storage",
        82 => "sk_select_reuseport",
        83 => "skb_ancestor_cgroup_id",
        84 => "sk_lookup_tcp",
        85 => "sk_lookup_udp",
        86 => "sk_release",
        87 => "map_push_elem",
        88 => "map_pop_elem",
        89 => "map_peek_elem",
        90 => "msg_push_data",
        91 => "msg_pop_data",
        92 => "rc_pointer_rel",
        93 => "spin_lock",
        94 => "spin_unlock",
        95 => "sk_fullsock",
        96 => "tcp_sock",
        97 => "skb_ecn_set_ce",
        98 => "get_listener_sock",
        99 => "skc_lookup_tcp",
        100 => "tcp_check_syncookie",
        101 => "sysctl_get_name",
        102 => "sysctl_get_current_value",
        103 => "sysctl_get_new_value",
        104 => "sysctl_set_new_value",
        105 => "strtol",
        106 => "strtoul",
        107 => "sk_storage_get",
        108 => "sk_storage_delete",
        109 => "send_signal",
        110 => "tcp_gen_syncookie",
        111 => "skb_output",
        112 => "probe_read_user",
        113 => "probe_read_kernel",
        114 => "probe_read_user_str",
        115 => "probe_read_kernel_str",
        116 => "tcp_send_ack",
        117 => "send_signal_thread",
        118 => "jiffies64",
        119 => "read_branch_records",
        120 => "get_ns_current_pid_tgid",
        121 => "xdp_output",
        122 => "get_netns_cookie",
        123 => "get_current_ancestor_cgroup_id",
        124 => "sk_assign",
        125 => "ktime_get_boot_ns",
        126 => "seq_printf",
        127 => "seq_write",
        128 => "sk_cgroup_id",
        129 => "sk_ancestor_cgroup_id",
        130 => "ringbuf_output",
        131 => "ringbuf_reserve",
        132 => "ringbuf_submit",
        133 => "ringbuf_discard",
        134 => "ringbuf_query",
        135 => "csum_level",
        136 => "skc_to_tcp6_sock",
        137 => "skc_to_tcp_sock",
        138 => "skc_to_tcp_timewait_sock",
        139 => "skc_to_tcp_request_sock",
        140 => "skc_to_udp6_sock",
        141 => "get_task_stack",
        142 => "load_hdr_opt",
        143 => "store_hdr_opt",
        144 => "reserve_hdr_opt",
        145 => "inode_storage_get",
        146 => "inode_storage_delete",
        147 => "d_path",
        148 => "copy_from_user",
        149 => "snprintf_btf",
        150 => "seq_printf_btf",
        151 => "skb_cgroup_classid",
        152 => "redirect_neigh",
        153 => "per_cpu_ptr",
        154 => "this_cpu_ptr",
        155 => "redirect_peer",
        156 => "task_storage_get",
        157 => "task_storage_delete",
        158 => "get_current_task_btf",
        159 => "bprm_opts_set",
        160 => "ktime_get_coarse_ns",
        161 => "ima_inode_hash",
        162 => "sock_from_file",
        163 => "check_mtu",
        164 => "for_each_map_elem",
        165 => "snprintf",
        166 => "sys_bpf",
        167 => "btf_find_by_name_kind",
        168 => "sys_close",
        169 => "timer_init",
        170 => "timer_set_callback",
        171 => "timer_start",
        172 => "timer_cancel",
        173 => "get_func_ip",
        174 => "get_attach_cookie",
        175 => "task_pt_regs",
        176 => "get_branch_snapshot",
        177 => "trace_vprintk",
        178 => "skc_to_unix_sock",
        179 => "kallsyms_lookup_name",
        180 => "find_vma",
        181 => "loop",
        182 => "strncmp",
        183 => "get_func_arg",
        184 => "get_func_ret",
        185 => "get_func_arg_cnt",
        186 => "get_retval",
        187 => "set_retval",
        188 => "xdp_get_buff_len",
        189 => "xdp_load_bytes",
        190 => "xdp_store_bytes",
        191 => "copy_from_user_task",
        192 => "skb_set_tstamp",
        193 => "ima_file_hash",
        194 => "kptr_xchg",
        195 => "map_lookup_percpu_elem",
        196 => "skc_to_mptcp_sock",
        197 => "dynptr_from_mem",
        198 => "ringbuf_reserve_dynptr",
        199 => "ringbuf_submit_dynptr",
        200 => "ringbuf_discard_dynptr",
        201 => "dynptr_read",
        202 => "dynptr_write",
        203 => "dynptr_data",
        204 => "tcp_raw_gen_syncookie_ipv4",
        205 => "tcp_raw_gen_syncookie_ipv6",
        206 => "tcp_raw_check_syncookie_ipv4",
        207 => "tcp_raw_check_syncookie_ipv6",
        208 => "ktime_get_tai_ns",
        209 => "user_ringbuf_drain",
        210 => "cgrp_storage_get",
        211 => "cgrp_storage_delete",
        _ => return format!("unresolved helper {id}"),
    };
    format!("{name} ({id})")
}
