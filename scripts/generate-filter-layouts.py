#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Generate captured-member facts from Linux 6.12.94 using the x86-64 Clang ABI.

No host libc headers, runtime pointer reads, or retained upstream C are used.
Development prerequisite: the existing libclang Python binding. Unknown/selector
dependent unions are recorded explicitly rather than interpreted generically.
"""
import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from clang import cindex

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "src/antinomie/monitor"
KERNEL = ROOT / "work/debian-6.12.94-1-trixie/core"
PREFIX = "linux-6.12.94/x86_64/"
# Recorded layout spelling -> exact pinned declaration and source header.
TYPES = {
    "open_how": ("struct open_how", "linux/openat2.h"),
    "clone_args": ("struct clone_args", "linux/sched.h"),
    "timespec": ("struct __kernel_timespec", "linux/time_types.h"),
    "timeval": ("struct __kernel_old_timeval", "linux/time_types.h"),
    "itimerspec": ("struct __kernel_itimerspec", "linux/time_types.h"),
    "itimerval": ("struct __kernel_old_itimerval", "linux/time_types.h"),
    "timezone": ("struct timezone", "linux/time.h"),
    "utimbuf": ("struct utimbuf", "linux/utime.h"),
    "tms": ("struct tms", "linux/times.h"),
    "timex": ("struct __kernel_timex", "linux/timex.h"),
    "stat": ("struct stat", "asm/stat.h"),
    "statfs": ("struct statfs", "asm/statfs.h"),
    "statx": ("struct statx", "linux/stat.h"),
    "rlimit": ("struct rlimit", "linux/resource.h"),
    "rlimit64": ("struct rlimit64", "linux/resource.h"),
    "rusage": ("struct rusage", "linux/resource.h"),
    "sysinfo": ("struct sysinfo", "linux/sysinfo.h"),
    "utsname": ("struct new_utsname", "linux/utsname.h"),
    "sched_param": ("struct sched_param", "linux/sched/types.h"),
    "sched_attr": ("struct sched_attr", "linux/sched/types.h"),
    "iovec": ("struct iovec", "linux/uio.h"),
    "pollfd": ("struct pollfd", "linux/poll.h"),
    "epoll_event": ("struct epoll_event", "linux/eventpoll.h"),
    "sock_fprog": ("struct sock_fprog", "linux/filter.h"),
    "sock_filter": ("struct sock_filter", "linux/filter.h"),
    "bpf_attr": ("union bpf_attr", "linux/bpf.h"),
    "bpf_insn": ("struct bpf_insn", "linux/bpf.h"),
    "bpf_map_info": ("struct bpf_map_info", "linux/bpf.h"),
    "bpf_func_info": ("struct bpf_func_info", "linux/bpf.h"),
    "bpf_line_info": ("struct bpf_line_info", "linux/bpf.h"),
    "bpf_core_relo": ("struct bpf_core_relo", "linux/bpf.h"),
    "cap_data": ("struct __user_cap_data_struct", "linux/capability.h"),
    "flock": ("struct flock", "asm/fcntl.h"),
    "f_owner_ex": ("struct f_owner_ex", "asm/fcntl.h"),
    "mount_attr": ("struct mount_attr", "linux/mount.h"),
    "mnt_id_req": ("struct mnt_id_req", "linux/mount.h"),
    "statmount": ("struct statmount", "linux/mount.h"),
    "futex_waitv": ("struct futex_waitv", "linux/futex.h"),
    "robust_list_head": ("struct robust_list_head", "linux/futex.h"),
    "landlock_ruleset_attr": ("struct landlock_ruleset_attr", "linux/landlock.h"),
    "landlock_path_beneath_attr": ("struct landlock_path_beneath_attr", "linux/landlock.h"),
    "landlock_net_port_attr": ("struct landlock_net_port_attr", "linux/landlock.h"),
    "keyctl_dh_params": ("struct keyctl_dh_params", "linux/keyctl.h"),
    "keyctl_kdf_params": ("struct keyctl_kdf_params", "linux/keyctl.h"),
    "keyctl_pkey_params": ("struct keyctl_pkey_params", "linux/keyctl.h"),
    "keyctl_pkey_query": ("struct keyctl_pkey_query", "linux/keyctl.h"),
    "prctl_mm_map": ("struct prctl_mm_map", "linux/prctl.h"),
    "ptrace_peeksiginfo_args": ("struct ptrace_peeksiginfo_args", "linux/ptrace.h"),
    "ptrace_rseq_configuration": ("struct ptrace_rseq_configuration", "linux/ptrace.h"),
    "ptrace_sud_config": ("struct ptrace_sud_config", "linux/ptrace.h"),
    "ptrace_syscall_info": ("struct ptrace_syscall_info", "linux/ptrace.h"),
    "seccomp_notif_sizes": ("struct seccomp_notif_sizes", "linux/seccomp.h"),
    "seccomp_metadata": ("struct seccomp_metadata", "linux/ptrace.h"),
    "perf_event_attr": ("struct perf_event_attr", "linux/perf_event.h"),
    "lsm_ctx": ("struct lsm_ctx", "linux/lsm.h"),
    "rseq": ("struct rseq", "linux/rseq.h"),
    "cachestat_range": ("struct cachestat_range", "linux/mman.h"),
    "cachestat": ("struct cachestat", "linux/mman.h"),
    "kexec_segment": ("struct kexec_segment", "linux/kexec.h"),
    "mq_attr": ("struct mq_attr", "linux/mqueue.h"),
    "tcp_ao_getsockopt": ("struct tcp_ao_getsockopt", "linux/tcp.h"),
    "tcp_zerocopy_receive": ("struct tcp_zerocopy_receive", "linux/tcp.h"),
    "shmid64_ds": ("struct shmid64_ds", "asm/shmbuf.h"),
    "shminfo64": ("struct shminfo64", "asm/shmbuf.h"),
    "msqid64_ds": ("struct msqid64_ds", "asm/msgbuf.h"),
    "semid64_ds": ("struct semid64_ds", "asm/sembuf.h"),
    "sembuf": ("struct sembuf", "linux/sem.h"),
    "seminfo": ("struct seminfo", "linux/sem.h"),
    "shm_info": ("struct shm_info", "linux/shm.h"),
    "msginfo": ("struct msginfo", "linux/msg.h"),
    "if_dqblk": ("struct if_dqblk", "linux/quota.h"),
    "if_dqinfo": ("struct if_dqinfo", "linux/quota.h"),
    "if_nextdqblk": ("struct if_nextdqblk", "linux/quota.h"),
    "fs_disk_quota": ("struct fs_disk_quota", "linux/dqblk_xfs.h"),
    "fs_quota_stat": ("struct fs_quota_stat", "linux/dqblk_xfs.h"),
    "fs_quota_statv": ("struct fs_quota_statv", "linux/dqblk_xfs.h"),
    "user_desc": ("struct user_desc", "asm/ldt.h"),
    "stack_t": ("stack_t", "asm/signal.h"),
    "sigaction": ("struct sigaction", "asm/signal.h"),
    "sigevent": ("struct sigevent", "linux/signal.h"),
    "siginfo_t": ("siginfo_t", "asm/siginfo.h"),
    "io_uring_params": ("struct io_uring_params", "linux/io_uring.h"),
    "xt_counters_info": ("struct xt_counters_info", "linux/netfilter/x_tables.h"),
}
SCALARS = {
    "int": ("int", True), "wait_status": ("int", True), "timer_t": ("int", True),
    "pid_t": ("int", True), "socklen_t": ("int", True), "unsigned_int": ("unsigned int", False),
    "u8": ("__u8", False), "u32": ("__u32", False), "uid_t": ("__u32", False),
    "gid_t": ("__u32", False), "u64": ("__u64", False), "size_t": ("__kernel_size_t", False),
    "loff_t": ("__s64", True), "time_t": ("__kernel_old_time_t", True),
    "unsigned_long": ("unsigned long", False), "address": ("unsigned long", False),
    "robust_list_head_pointer": ("unsigned long", False),
}
# union bpf_attr's branches and the commands (enum bpf_cmd) that read each: a
# named branch by its field name, an anonymous one by its first member. Every
# member of a branch is qualified by bpf's first argument being one of these.
BPF_BRANCHES = {
    "map_type": [0],                                # BPF_MAP_CREATE
    "map_fd": [1, 2, 3, 4, 21, 22],                 # BPF_MAP_*_ELEM, GET_NEXT_KEY, FREEZE
    "batch": [24, 25, 26, 27],                      # BPF_MAP_*_BATCH
    "prog_type": [5],                               # BPF_PROG_LOAD
    "pathname": [6, 7],                             # BPF_OBJ_PIN, BPF_OBJ_GET
    "target_fd": [8, 9],                            # BPF_PROG_ATTACH, BPF_PROG_DETACH
    "test": [10],                                   # BPF_PROG_TEST_RUN
    "start_id": [11, 12, 13, 14, 19, 23, 30, 31],   # BPF_*_GET_NEXT_ID, BPF_*_GET_FD_BY_ID
    "info": [15],                                   # BPF_OBJ_GET_INFO_BY_FD
    "query": [16],                                  # BPF_PROG_QUERY
    "raw_tracepoint": [17],                         # BPF_RAW_TRACEPOINT_OPEN
    "btf": [18],                                    # BPF_BTF_LOAD
    "task_fd_query": [20],                          # BPF_TASK_FD_QUERY
    "link_create": [28],                            # BPF_LINK_CREATE
    "link_update": [29],                            # BPF_LINK_UPDATE
    "link_detach": [34],                            # BPF_LINK_DETACH
    "enable_stats": [32],                           # BPF_ENABLE_STATS
    "iter_create": [33],                            # BPF_ITER_CREATE
    "prog_bind_map": [35],                          # BPF_PROG_BIND_MAP
    "token_create": [36],                           # BPF_TOKEN_CREATE
}
# BPF_LINK_CREATE's members from this bit offset on are a union the attach
# type selects (a member of the attr, not an argument): not qualified.
BPF_LINK_CREATE_ATTACH_UNION = 128

def first_member(declaration):
    for child in declaration.get_children():
        if child.kind == cindex.CursorKind.FIELD_DECL:
            if child.spelling:
                return child.spelling
            return first_member(child.type.get_canonical().get_declaration())
        if child.kind in (cindex.CursorKind.STRUCT_DECL, cindex.CursorKind.UNION_DECL):
            name = first_member(child)
            if name:
                return name
    return None

def bpf_attr_members(root_type):
    """Each branch of union bpf_attr walked with the commands that read it."""
    declaration = root_type.get_canonical().get_declaration()
    children = list(declaration.get_children())
    field_types = {child.type.get_canonical().get_declaration().hash
                   for child in children if child.kind == cindex.CursorKind.FIELD_DECL}
    output, unsupported = [], []
    for child in children:
        if child.kind == cindex.CursorKind.FIELD_DECL:
            key, prefix = child.spelling, child.spelling + "."
        elif child.kind in (cindex.CursorKind.STRUCT_DECL, cindex.CursorKind.UNION_DECL) and child.hash not in field_types:
            key, prefix = first_member(child), ""
        else:
            continue
        commands = BPF_BRANCHES.get(key)
        if commands is None:
            unsupported.append(f"{key}: BPF branch without a command mapping")
            continue
        members, missing = walk_members(child.type, prefix, 0, commands, (declaration.hash,))
        if key == "link_create":
            for member in members:
                if member["bit_offset"] >= BPF_LINK_CREATE_ATTACH_UNION:
                    missing.append(member["member"] + ": BPF_LINK_CREATE member selected by attach_type, not qualified")
            members = [member for member in members if member["bit_offset"] < BPF_LINK_CREATE_ATTACH_UNION]
        output.extend(members); unsupported.extend(missing)
    unique = {}
    for member in output:
        unique[(member["member"], member["bit_offset"], tuple(member["selector"]["values"]))] = member
    return sorted(unique.values(), key=lambda m: (m["member"], m["bit_offset"])), sorted(set(unsupported))

# Dynamic/selector capture families not fully represented by C prototypes.
EXTRA_BINDINGS = {
    "sock_fprog": [(54, 3), (157, 2), (317, 2)],
    "msghdr": [(46, 1), (47, 1)], "mmsghdr[]": [(299, 1), (307, 1)],
    "iovec[]": [(19, 1), (20, 1), (295, 1), (296, 1), (310, 1), (310, 3), (311, 1), (311, 3), (327, 1), (328, 1)],
    "sockaddr": [(42, 1), (49, 1), (43, 1), (51, 1), (52, 1), (288, 1), (44, 4), (45, 4)],
    "bpf_map_info": [(321, 1)], "cap_data[]": [(125, 1), (126, 1)],
    "bpf_attr": [(321, 1)], "siginfo_t[]": [(101, 3)],
    "iovec": [(101, 3)],
    "linger": [(54, 3), (55, 3)],
    "bpf_func_info[]": [(321, 1)], "bpf_line_info[]": [(321, 1)], "bpf_core_relo[]": [(321, 1)],
    "bpf_insn[]": [(321, 1)], "sock_filter[]": [(54, 3), (55, 3), (157, 2), (317, 2)],
    "cmsghdr[]": [(46, 1), (47, 1), (299, 1), (307, 1)],
    "f_owner_ex": [(72, 2)], "flock": [(72, 2)], "uid_t[2]": [(72, 2)],
    "keyctl_dh_params": [(250, 1)], "keyctl_kdf_params": [(250, 4)],
    "keyctl_pkey_params": [(250, 1)], "keyctl_pkey_query": [(250, 4)],
    "prctl_mm_map": [(157, 2)], "landlock_path_beneath_attr": [(445, 2)],
    "landlock_net_port_attr": [(445, 2)], "seccomp_notif_sizes": [(317, 2)],
    "stack_t": [(131, 0), (131, 1)], "user_desc": [(154, 1), (101, 3)],
    "ptrace_peeksiginfo_args": [(101, 2)], "ptrace_syscall_info": [(101, 3)],
    "ptrace_rseq_configuration": [(101, 3)], "ptrace_sud_config": [(101, 3)],
    "seccomp_metadata": [(101, 3)],
    "if_dqblk": [(179, 3), (443, 3)], "if_dqinfo": [(179, 3), (443, 3)],
    "if_nextdqblk": [(179, 3), (443, 3)], "fs_disk_quota": [(179, 3), (443, 3)],
    "fs_quota_stat": [(179, 3), (443, 3)], "fs_quota_statv": [(179, 3), (443, 3)],
    "shmid64_ds": [(31, 2)], "shminfo64": [(31, 2)], "shm_info": [(31, 2)],
    "msqid64_ds": [(71, 2)], "msginfo": [(71, 2)], "semid64_ds": [(66, 3)], "seminfo": [(66, 3)],
    "u64": [(157, 4), (101, 3), (72, 2), (303, 3)],
    "u32": [(125, 0), (126, 0), (157, 1), (157, 2), (101, 3), (317, 2), (309, 0), (309, 1), (202, 0), (202, 4)],
    "u32[]": [(321, 1)], "u64[]": [(321, 1), (458, 1)],
    "user_regs_struct": [(101, 3)], "user_i387_struct": [(101, 3)],
    "tcp_ao_getsockopt": [(55, 3)], "tcp_zerocopy_receive": [(55, 3)],
    "xt_counters_info": [(54, 3)],
}
META = [
    {"member": "complete", "kind": "boolean", "detail": "Whole captured argument field complete"},
    {"member": "captured_size", "kind": "integer", "detail": "Recorded captured octets"},
    {"member": "expected_size", "kind": "integer", "detail": "Recorded logical extent, absent when unknown"},
    {"member": "status", "kind": "integer", "detail": "Capture status enum, absent without a final field record"},
    {"member": "capture_error", "kind": "integer", "detail": "Signed kernel capture error"},
    {"member": "layout", "kind": "text", "detail": "Exact recorded layout identifier"},
]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def extract_record(source, name):
    match = re.search(r"struct\s+" + re.escape(name) + r"\s*\{", source)
    if not match:
        return ""
    depth = 1
    end = match.end()
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + ";\n"

def walk_members(record_type, prefix="", offset=0, bpf=None, ancestors=(), common_union_members=None):
    canonical = record_type.get_canonical()
    declaration = canonical.get_declaration()
    if declaration.hash in ancestors:
        return [], ["recursive record"]
    output, unsupported = [], []
    children = list(declaration.get_children())
    # A named member of an unnamed record type is reached through its field;
    # in a bpf branch the record's own declaration is not walked again.
    named_types = {child.type.get_canonical().get_declaration().hash
                   for child in children if child.kind == cindex.CursorKind.FIELD_DECL and child.spelling}
    for field in children:
        if field.kind != cindex.CursorKind.FIELD_DECL:
            if bpf and field.hash in named_types:
                continue
            # Anonymous BPF structs are exposed by Clang as record declarations.
            if (bpf or common_union_members) and field.kind in (cindex.CursorKind.STRUCT_DECL, cindex.CursorKind.UNION_DECL):
                base = offset
                if bpf:
                    # Its members' offsets are relative to the anonymous record:
                    # place it by its first member's offset in this record.
                    first = first_member(field)
                    inner = canonical.get_offset(first) if first else -1
                    if inner < 0:
                        unsupported.append(prefix + (first or "?") + ": unavailable anonymous record offset")
                        continue
                    base = offset + inner
                members, missing = walk_members(field.type, prefix, base, bpf, ancestors + (declaration.hash,), common_union_members)
                output.extend(members); unsupported.extend(missing)
            continue
        name = prefix + field.spelling
        if not field.spelling and field.is_bitfield():
            unsupported.append(name + "(unnamed bit field): padding, not a semantic value")
            continue
        if field.spelling in ("pad", "__pad", "__padding", "_pad") or field.spelling.startswith(("__unused", "__reserved")) \
                or re.fullmatch(r"resv\d*", field.spelling):
            unsupported.append(name + ": reserved/padding, not a semantic value")
            continue
        bits = field.get_field_offsetof()
        if bits < 0:
            unsupported.append(name + ": unavailable offset"); continue
        value_type = field.type.get_canonical()
        size = value_type.get_size()
        at = offset + bits
        if size <= 0:
            unsupported.append(name + ": incomplete or nonaddressable field")
            continue
        if value_type.kind == cindex.TypeKind.RECORD:
            union = value_type.get_declaration().kind == cindex.CursorKind.UNION_DECL
            if union and not bpf and not common_union_members:
                unsupported.append(name + ": union selector unavailable"); continue
            children, missing = walk_members(field.type, name + "." if field.spelling else prefix, at, bpf, ancestors + (declaration.hash,), common_union_members)
            output.extend(children); unsupported.extend(missing); continue
        item = {"member": name, "bit_offset": at, "bit_size": field.get_bitfield_width() if field.is_bitfield() else size * 8,
                "size": size, "kind": "integer", "signed": value_type.kind in (cindex.TypeKind.CHAR_S, cindex.TypeKind.SCHAR,
                    cindex.TypeKind.SHORT, cindex.TypeKind.INT, cindex.TypeKind.LONG, cindex.TypeKind.LONGLONG),
                "pointer": value_type.kind == cindex.TypeKind.POINTER, "byte_order": "little"}
        if value_type.kind == cindex.TypeKind.CONSTANTARRAY:
            element = value_type.element_type.get_canonical()
            count = value_type.element_count
            if element.kind in (cindex.TypeKind.CHAR_S, cindex.TypeKind.CHAR_U, cindex.TypeKind.SCHAR, cindex.TypeKind.UCHAR):
                item.update(kind="text", signed=False)
            elif element.kind == cindex.TypeKind.RECORD:
                for index in range(min(count, 64)):
                    children, missing = walk_members(element, name + f"[{index}].", at + index * element.get_size() * 8, bpf, ancestors + (declaration.hash,))
                    output.extend(children); unsupported.extend(missing)
                if count > 64: unsupported.append(name + ": fixed array beyond 64 elements")
                continue
            elif element.get_size() in (1, 2, 4, 8):
                for index in range(min(count, 64)):
                    child = dict(item, member=name + f"[{index}]", bit_offset=at + index * element.get_size() * 8,
                                 size=element.get_size(), bit_size=element.get_size() * 8,
                                 signed=element.kind in (cindex.TypeKind.INT, cindex.TypeKind.LONG, cindex.TypeKind.LONGLONG))
                    output.append(child)
                continue
            else: unsupported.append(name + ": unsupported array element"); continue
        elif value_type.kind == cindex.TypeKind.INCOMPLETEARRAY:
            unsupported.append(name + ": variable trailing array"); continue
        elif size not in (1, 2, 4, 8):
            unsupported.append(name + ": unsupported scalar width"); continue
        if bpf:
            item["selector"] = {"argument_index": 0, "values": list(bpf), "syscall_numbers": [321]}
        if common_union_members and name not in common_union_members:
            unsupported.append(name + ": signal union member requires si_code selector qualification")
            continue
        output.append(item)
    unique = {}
    for member in output:
        unique[(member["member"], member["bit_offset"], tuple(member.get("selector", {}).get("values", [])))] = member
    return sorted(unique.values(), key=lambda m: (m["member"], m["bit_offset"])), sorted(set(unsupported))

def generate(kernel):
    version = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\d+)\s*$", (kernel / "Makefile").read_text(), re.M))
    if [version.get(key) for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL")] != ["6", "12", "94"]:
        raise ValueError("captured member facts require Linux 6.12.94")
    schema_path = MONITOR / "protocol/native-syscalls.json"
    schema = json.loads(schema_path.read_text())
    by_number = {row["number"]: row for row in schema["syscalls"]}
    capture_paths = sorted(set((kernel / "kernel/antinomie").glob("*capture.c"))
                           | set((kernel / "kernel/antinomie").glob("capture_*.c")))
    capture_source = "\n".join(path.read_text() for path in capture_paths)
    captured = set(re.findall(r'LAYOUT\("([^"]+)"\)', capture_source))
    # Explicit macro rows (the syscall by its __NR_ name), including the
    # additional phase argument.
    by_name = {row["name"]: row["number"] for row in schema["syscalls"]}
    direct = []
    for macro, nr, arg, rest, layout in re.findall(r'(INPUT_FIELD|OUTPUT_FIELD|FIXED_FIELD|RECORDS_FIELD)\((\w+),\s*(\d+),\s*(.*?),\s*"([^"]+)"\)', capture_source):
        captured.add(layout)
        number = int(nr) if nr.isdigit() else by_name.get(nr.removeprefix("__NR_"))
        if number is not None:
            direct.append((layout, number, int(arg)))
    sources = {str(path.relative_to(kernel)): sha(path) for path in capture_paths}
    sources["Makefile"] = sha(kernel / "Makefile")
    sources["scripts/headers_install.sh"] = sha(kernel / "scripts/headers_install.sh")
    layouts = []
    with tempfile.TemporaryDirectory(prefix="ant-layout-") as temporary:
        overlay = Path(temporary)
        (overlay / "asm").mkdir()
        (overlay / "linux").mkdir()
        # Same removal as pinned scripts/headers_install.sh: compiler-only
        # declarations are not part of installed userspace ABI headers.
        for header in (kernel / "include/uapi/linux").rglob("*.h"):
            text = header.read_text()
            cleaned = re.sub(r"^#include <linux/compiler(?:_types)?\.h>[^\n]*$", "", text, flags=re.M)
            if cleaned != text:
                target = overlay / "linux" / header.relative_to(kernel / "include/uapi/linux")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(cleaned)
                sources[str(header.relative_to(kernel))] = sha(header)
        for directory in (kernel / "arch/x86/include/uapi/asm", kernel / "include/uapi/asm-generic"):
            for header in directory.glob("*.h"):
                text = header.read_text()
                cleaned = re.sub(r"^#include <linux/compiler(?:_types)?\.h>[^\n]*$", "", text, flags=re.M)
                if cleaned != text:
                    target = overlay / ("asm" if directory.name == "asm" else "asm-generic") / header.name
                    target.parent.mkdir(exist_ok=True)
                    target.write_text(cleaned)
                    sources[str(header.relative_to(kernel))] = sha(header)
        # Mirror Kbuild's generic UAPI fallback, while architecture headers win.
        arch = kernel / "arch/x86/include/uapi/asm"
        for header in (kernel / "include/uapi/asm-generic").glob("*.h"):
            if not (arch / header.name).exists():
                (overlay / "asm" / header.name).write_text("#include <asm-generic/" + header.name + ">\n")
        # UAPI structures do not use syscall numbers. Satisfy the actual x86
        # include using constants generated from the same pinned native table.
        table_path = kernel / "arch/x86/entry/syscalls/syscall_64.tbl"
        syscall_definitions = ["#define __NR_" + row["name"] + " " + str(row["number"]) for row in schema["syscalls"]]
        (overlay / "asm/unistd_64.h").write_text("\n".join(syscall_definitions) + "\n")
        sources[str(table_path.relative_to(kernel))] = sha(table_path)
        socket_source_path = kernel / "include/linux/socket.h"
        socket_source = socket_source_path.read_text()
        sources[str(socket_source_path.relative_to(kernel))] = sha(socket_source_path)
        extras = "#define __user\n#include <linux/socket.h>\n"
        for name in ("user_msghdr", "mmsghdr", "cmsghdr", "linger"):
            extras += extract_record(socket_source, name)
        # sockaddr has a flexible union; keep only its compiler-derived family
        # once the actual pinned record is parsed.
        extras += "typedef __kernel_sa_family_t sa_family_t;\n" + extract_record(socket_source, "sockaddr").replace("DECLARE_FLEX_ARRAY(char, sa_data);", "char sa_data[0];")
        special = {"msghdr": "struct user_msghdr", "mmsghdr": "struct mmsghdr", "cmsghdr": "struct cmsghdr",
                   "linger": "struct linger", "sockaddr": "struct sockaddr"}
        for relative, names in {
            "include/linux/sched.h": ["sched_param"],
            "include/linux/types.h": ["ustat"],
            "arch/x86/include/asm/user_64.h": ["user_regs_struct", "user_i387_struct"],
        }.items():
            source_path = kernel / relative
            sources[relative] = sha(source_path)
            for name in names:
                special[name] = "struct " + name
                # Kernel-only user ABI records are extracted verbatim only in
                # the temporary compiler input, never copied into product code.
                extras += extract_record(source_path.read_text(), name)
        captured.update(special)
        for layout in sorted(captured):
            array = re.search(r"\[(\d*)\]$", layout)
            base = re.sub(r"\[.*\]$", "", layout)
            count = int(array.group(1)) if array and array.group(1) else None
            expr, header = TYPES.get(base, (None, None))
            if base in SCALARS: expr, _ = SCALARS[base]; header = "linux/time_types.h"
            if base in special: expr = special[base]; header = "linux/uio.h"
            if not expr:
                layouts.append({"layout": PREFIX + layout, "supported": False, "reason": "no qualified pinned declaration/selector mapping"})
                continue
            code = "#include <linux/types.h>\n#include <" + header + ">\n"
            if base in special: code += extras
            if header == "linux/shm.h":
                code = code.replace("#include <linux/shm.h>", "#define _LINUX_IPC_H\n#include <linux/ipc.h>\n" +
                    extract_record((kernel / "include/uapi/linux/shm.h").read_text(), base))
            code += "typedef " + expr + " __ant_layout;\n"
            args = ["-std=gnu11", "-target", "x86_64-linux-gnu", "-nostdinc", "-D__x86_64__", "-D__user=", "-D__force=", "-D__attribute_const__=",
                    "-I" + str(overlay), "-I" + str(kernel / "arch/x86/include/uapi"), "-I" + str(kernel / "include/uapi")]
            unit = cindex.Index.create().parse("members.c", args=args, unsaved_files=[("members.c", code)])
            errors = [str(d) for d in unit.diagnostics if d.severity >= cindex.Diagnostic.Error]
            if errors:
                diagnostics = [e.replace(str(kernel) + "/", "").replace(str(overlay) + "/", "uapi-overlay/") for e in errors]
                layouts.append({"layout": PREFIX + layout, "supported": False, "reason": "pinned declaration does not compile without unsupported dependencies", "diagnostics": diagnostics})
                continue
            typedef = next((cursor for cursor in unit.cursor.get_children() if cursor.spelling == "__ant_layout"), None)
            if not typedef: raise ValueError("compiler did not emit layout typedef")
            root_type = typedef.underlying_typedef_type
            stride = root_type.get_size()
            if stride <= 0:
                layouts.append({"layout": PREFIX + layout, "supported": False,
                    "reason": "pinned declaration is incomplete or has no constant ABI size"})
                continue
            if base in SCALARS:
                members = [{"member": "value", "bit_offset": 0, "bit_size": stride * 8, "size": stride,
                    "kind": "integer", "signed": SCALARS[base][1], "pointer": base in ("address", "robust_list_head_pointer"), "byte_order": "little"}]
                unsupported = []
            else:
                if base == "bpf_attr":
                    members, unsupported = bpf_attr_members(root_type)
                else:
                    members, unsupported = walk_members(root_type,
                        common_union_members={"si_signo", "si_errno", "si_code"} if base == "siginfo_t" else None)
            layout_sources = {}
            for include in unit.get_includes():
                path = Path(include.include.name)
                if path.is_relative_to(overlay):
                    relative = path.relative_to(overlay)
                    original = kernel / "include/uapi" / relative
                    if original.is_file():
                        key = str(original.relative_to(kernel)); layout_sources[key] = sha(original); sources[key] = layout_sources[key]
                if path.is_relative_to(kernel):
                    key = str(path.relative_to(kernel)); layout_sources[key] = sha(path); sources[key] = layout_sources[key]
            layouts.append({"layout": PREFIX + layout, "supported": bool(members), "c_type": expr,
                "stride": stride, "array": bool(array), "array_count": count, "members": members,
                "unsupported_members": unsupported, "sources": sorted(layout_sources),
                **({} if members else {"reason": "all known members require an unqualified union selector"})})
    required_sizes = {"open_how": 24, "clone_args": 88, "sock_fprog": 16,
                      "epoll_event": 12, "timespec": 16, "user_regs_struct": 216}
    for name, size in required_sizes.items():
        facts = next(layout for layout in layouts if layout["layout"] == PREFIX + name)
        if not facts["supported"] or facts.get("stride") != size:
            raise ValueError(f"representative {name} ABI changed; expected {size}, review pinned inputs")
    required_offsets = {"open_how": {"flags": 0, "mode": 64, "resolve": 128},
                        "sock_fprog": {"len": 0, "filter": 64},
                        "epoll_event": {"events": 0, "data": 32},
                        "clone_args": {"flags": 0, "pidfd": 64, "child_tid": 128, "parent_tid": 192},
                        "siginfo_t": {"si_signo": 0, "si_errno": 32, "si_code": 64}}
    for name, offsets in required_offsets.items():
        facts = next(layout for layout in layouts if layout["layout"] == PREFIX + name)
        actual = {member["member"]: member["bit_offset"] for member in facts.get("members", [])}
        if any(actual.get(member) != offset for member, offset in offsets.items()):
            raise ValueError(f"representative {name} member offsets changed; review pinned inputs")
    for facts in layouts:
        if not facts["supported"]: continue
        if facts["stride"] <= 0: raise ValueError("supported layout has no ABI extent")
        for member in facts["members"]:
            if member["bit_offset"] < 0 or member["bit_size"] <= 0 or member["size"] <= 0:
                raise ValueError("nonaddressable/incomplete compiler member escaped validation")
            if member["bit_offset"] + member["bit_size"] > facts["stride"] * 8:
                raise ValueError("compiler member extends outside its captured layout")
    bindings = {}
    def bind(layout, nr, index):
        row = by_number.get(nr)
        if not row or index >= len(row["arguments"]): return
        arg = row["arguments"][index]
        bindings.setdefault(PREFIX + layout, set()).add((nr, index, arg["name"]))
    for layout, nr, index in direct: bind(layout, nr, index)
    for layout, cases in EXTRA_BINDINGS.items():
        for nr, index in cases: bind(layout, nr, index)
    for layout in layouts:
        expr = layout.get("c_type")
        if expr:
            for row in schema["syscalls"]:
                for index, arg in enumerate(row["arguments"]):
                    if re.search(r"\b" + re.escape(expr) + r"\s*\*", arg["c_type"]):
                        bind(layout["layout"][len(PREFIX):], row["number"], index)
        layout["arguments"] = [{"syscall_number": n, "argument_index": i, "name": a}
            for n, i, a in sorted(bindings.get(layout["layout"], []))]
    return {"format_version": 1, "kernel_version": "6.12.94", "architecture": "x86_64",
        "endianness": "little", "compiler_target": "x86_64-linux-gnu",
        "provenance": {"native_schema_sha256": sha(schema_path), "source_sha256": dict(sorted(sources.items())),
            "generator": "scripts/generate-filter-layouts.py",
            "compiler_library_sha256": sha(Path(cindex.conf.lib._name)),
            "method": "libclang target ABI over pinned UAPI and extracted pinned kernel-only user ABI records; no host libc"},
        "phase_policy": "Latest phase uniquely supplying an applicable member; conflicting captures in one phase are Missing",
        "array_policy": "Fixed arrays use the compiler count; variable arrays permit any nonnegative decimal index with checked arithmetic and actual captured-member extent; first 64 indices are completion examples, not a decode limit",
        "argument_names": sorted({argument["name"] for row in schema["syscalls"] for argument in row["arguments"]}),
        "metadata_members": META, "layouts": layouts}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=KERNEL)
    parser.add_argument("--output", type=Path, default=MONITOR / "protocol/captured-layout-members.json")
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    generated = json.dumps(generate(options.kernel.resolve()), indent=2, sort_keys=False) + "\n"
    if options.check:
        if options.output.read_text() != generated: raise SystemExit("captured-layout inventory differs; regenerate and review")
        print("captured-layout inventory matches pinned compiler facts")
    else:
        options.output.write_text(generated)
        print("wrote", options.output)
if __name__ == "__main__":
    main()
