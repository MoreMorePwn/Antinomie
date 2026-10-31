#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Generate native ABI metadata from the pinned table and parsed C declarations.

Development prerequisite: installed libclang Python bindings (tested 18.1.1).
Clang is used only for declaration grammar, never to infer ABI sizes from the
synthetic typedefs. Actual capture extents belong to reviewed kernel decoders.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from clang import cindex

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "work/debian-6.12.94-1-trixie/core"
# One generated table per architecture: its syscall table, the table's ABI
# columns that make up the native ABI, the expected row count, the per-arch
# C header the guest recorder includes (<asm/antinomie_syscalls.h>) and the
# preprocessor symbols that select the arch's prototypes in syscalls.h.
# arm64 and riscv64 select CLONE_BACKWARDS (clone's tls before child_tid);
# both use the asm-generic numbering, arm64 from its own copy of the table.
ARCHES = {
    "x86_64": {"table": "arch/x86/entry/syscalls/syscall_64.tbl", "abis": ("common", "64"),
               "count": 375, "c_header": "arch/x86/include/asm/antinomie_syscalls.h",
               "defines": ("-DCONFIG_X86_64=1",)},
    "aarch64": {"table": "arch/arm64/tools/syscall_64.tbl",
                "abis": ("common", "64", "renameat", "rlimit", "memfd_secret"),
                "count": 318, "c_header": "arch/arm64/include/asm/antinomie_syscalls.h",
                "defines": ("-DCONFIG_ARM64=1", "-DCONFIG_CLONE_BACKWARDS=1"),
                "clone_backwards": True},
    # arm EABI, the AArch32 compat ABI of arm64 (arch/arm64/tools/syscall_32.tbl
    # has the same numbers and names; its oabi rows are OABI only): an ILP32
    # table whose 64-bit arguments take aligned register pairs, written as the
    # compat header of arm64's recorder.
    "arm": {"table": "arch/arm/tools/syscall.tbl", "abis": ("common",),
            "count": 415, "c_header": "arch/arm64/include/asm/antinomie_compat_syscalls.h",
            "compat": True, "bits": 32,
            "defines": ("-DCONFIG_ARM=1", "-DCONFIG_CLONE_BACKWARDS=1", "-D__ARCH_WANT_STAT64=1",
                        "-DCONFIG_OLD_SIGACTION=1", "-DCONFIG_OLD_SIGSUSPEND3=1", "-DCONFIG_HAVE_UID16=1",
                        "-D__ARCH_WANT_SYS_OLD_GETRLIMIT=1"),
            "clone_backwards": True,
            "declarations": """
long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len);
long sys_mmap2(unsigned long addr, unsigned long len, unsigned long prot,
               unsigned long flags, unsigned long fd, unsigned long pgoff);
long sys_sigreturn_wrapper(void);
long sys_rt_sigreturn_wrapper(void);
long sys_statfs64_wrapper(const char *pathname, size_t sz, struct statfs64 *buf);
long sys_fstatfs64_wrapper(unsigned int fd, size_t sz, struct statfs64 *buf);
"""},
    "riscv64": {"table": "scripts/syscall.tbl",
                "abis": ("common", "64", "riscv", "rlimit", "memfd_secret"),
                "count": 319, "c_header": "arch/riscv/include/asm/antinomie_syscalls.h",
                "defines": ("-DCONFIG_RISCV=1", "-DCONFIG_CLONE_BACKWARDS=1"),
                "clone_backwards": True,
                "declarations": """
long sys_riscv_flush_icache(uintptr_t start, uintptr_t end, uintptr_t flags);
long sys_riscv_hwprobe(struct riscv_hwprobe *pairs, size_t pair_count, size_t cpusetsize,
                       unsigned long *cpus, unsigned int flags);
"""},
}
DECLARATION = re.compile(r"asmlinkage\s+long\s+(sys_\w+)\s*\((.*?)\)\s*;", re.S)
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
KEYWORDS = {"const", "unsigned", "signed", "long", "short", "int", "char",
            "void", "struct", "union", "enum", "volatile", "restrict", "bool"}

# Architecture-only entry points are absent from the generic syscall header.
ARCH_DECLARATIONS = """
long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot,
              unsigned long flags, unsigned long fd, unsigned long offset);
long sys_arch_prctl(int option, unsigned long arg2);
long sys_modify_ldt(int func, void *ptr, unsigned long bytecount);
long sys_iopl(unsigned int level);
long sys_rt_sigreturn(void);
"""

# Names omitted by generic prototypes, checked against the pinned native
# SYSCALL_DEFINE declarations (clone uses the normal x86-64 ordering; the
# CLONE_BACKWARDS order is CLONE_BACKWARDS_NAMES).
ARGUMENT_NAMES = {
    "rt_sigaction": ("kernel/signal.c", ("sig", "act", "oact", "sigsetsize")),
    "clone": ("kernel/fork.c", ("clone_flags", "newsp", "parent_tidptr", "child_tidptr", "tls")),
    "socket": ("net/socket.c", ("family", "type", "protocol")),
    "socketpair": ("net/socket.c", ("family", "type", "protocol", "usockvec")),
    "connect": ("net/socket.c", ("fd", "uservaddr", "addrlen")),
    "bind": ("net/socket.c", ("fd", "umyaddr", "addrlen")),
    "listen": ("net/socket.c", ("fd", "backlog")),
    "accept": ("net/socket.c", ("fd", "upeer_sockaddr", "upeer_addrlen")),
    "accept4": ("net/socket.c", ("fd", "upeer_sockaddr", "upeer_addrlen", "flags")),
    "getsockname": ("net/socket.c", ("fd", "usockaddr", "usockaddr_len")),
    "getpeername": ("net/socket.c", ("fd", "usockaddr", "usockaddr_len")),
    "sendto": ("net/socket.c", ("fd", "buff", "len", "flags", "addr", "addr_len")),
    "recvfrom": ("net/socket.c", ("fd", "ubuf", "size", "flags", "addr", "addr_len")),
    "shutdown": ("net/socket.c", ("fd", "how")),
    "io_submit": ("fs/aio.c", ("ctx_id", "nr", "iocbpp")),
    "pselect6": ("fs/select.c", ("n", "inp", "outp", "exp", "tsp", "sig")),
    "ppoll": ("fs/select.c", ("ufds", "nfds", "tsp", "sigmask", "sigsetsize")),
    # arm: calls syscalls.h declares without names.
    "send": ("net/socket.c", ("fd", "buff", "len", "flags")),
    "recv": ("net/socket.c", ("fd", "ubuf", "size", "flags")),
    "sigaction": ("arch/arm/kernel/signal.c", ("sig", "act", "oact")),
    "pselect6_time64": ("fs/select.c", ("n", "inp", "outp", "exp", "tsp", "sig")),
    "ppoll_time64": ("fs/select.c", ("ufds", "nfds", "tsp", "sigmask", "sigsetsize")),
}
CLONE_BACKWARDS_NAMES = ("kernel/fork.c", ("clone_flags", "newsp", "parent_tidptr", "tls", "child_tidptr"))

# A 32-bit ABI passes a 64-bit argument in a pair of registers, the pair
# starting at an even register (arm EABI; little endian: the low word first),
# so its records' six argument slots are registers, not C arguments.
WIDE_TYPES = {"loff_t", "u64", "__u64", "s64", "__s64", "long long", "unsigned long long"}

# arm's private calls (arch/arm/include/uapi/asm/unistd.h __ARM_NR_*, from
# 0x0f0000), handled by arm_syscall() and arm64's compat_arm_syscall(): in the
# JSON table for the host's names, not in the guest's C table.
ARM_PRIVATE = (
    (0x0f0001, "breakpoint", ()),
    (0x0f0002, "cacheflush", (("start", "unsigned long"), ("end", "unsigned long"), ("flags", "int"))),
    (0x0f0003, "usr26", ()),
    (0x0f0004, "usr32", ()),
    (0x0f0005, "set_tls", (("tls", "unsigned long"),)),
    (0x0f0006, "get_tls", ()),
)

# The x86-64 call (the family) each arm call is the same operation as, for the
# host's rules, which key on names: the same arguments at the same places (a
# prefix of the family's: send is sendto without an address), except the
# argument indexes listed, whose values differ (mmap2's offset counts pages).
# Calls absent here keep their own name (truncate64's register pair, _llseek).
ARM_FAMILIES = {
    **{f"{name}32": name for name in (
        "getuid", "getgid", "geteuid", "getegid", "setuid", "setgid", "setreuid", "setregid",
        "setresuid", "getresuid", "setresgid", "getresgid", "getgroups", "setgroups",
        "chown", "lchown", "fchown", "setfsuid", "setfsgid")},
    **{f"{name}64": name for name in (
        "clock_gettime", "clock_settime", "clock_adjtime", "timer_gettime", "timer_settime",
        "timerfd_gettime", "timerfd_settime")},
    **{f"{name}_time64": name for name in (
        "clock_getres", "clock_nanosleep", "utimensat", "pselect6", "ppoll", "io_pgetevents",
        "recvmmsg", "mq_timedsend", "mq_timedreceive", "semtimedop", "rt_sigtimedwait",
        "futex", "sched_rr_get_interval")},
    "stat64": "stat", "lstat64": "lstat", "fstat64": "fstat", "fstatat64": "newfstatat",
    "fcntl64": "fcntl", "ugetrlimit": "getrlimit", "_newselect": "select",
    "mmap2": "mmap", "send": "sendto", "recv": "recvfrom", "sendfile64": "sendfile",
}
ARM_FAMILY_DIFFERENCES = {"mmap2": {5}}

# The compat header's second table: the native call an AArch32 call is, for
# the recorder to capture it with the native code (its records keep the arm
# number and ABI). Only calls whose arguments line up by name with the native
# call and whose objects have one layout on ILP32 and LP64: strings, bytes,
# 32-bit and fixed-width values, sockaddr, time64 values. The exec calls'
# vectors of 32-bit pointers are read as such by the recorder.
SAME_LAYOUT_POINTERS = {
    "const char *", "char *", "void *", "const void *", "int *", "unsigned int *", "u32 *",
    "u64 *", "loff_t *", "uid_t *", "gid_t *", "struct sockaddr *", "struct pollfd *",
    "struct __kernel_timespec *", "const struct __kernel_timespec *",
    "struct __kernel_itimerspec *", "const struct __kernel_itimerspec *",
    "sigset_t *", "const sigset_t *", "struct epoll_event *", "struct io_event *",
    "struct sembuf *", "struct file_handle *", "struct sched_param *", "struct sched_attr *",
    "struct futex_waitv *", "struct new_utsname *", "struct linux_dirent64 *", "struct statx *",
    "cap_user_header_t", "cap_user_data_t",
    "const cap_user_data_t",
}
# 32-bit signed types: the recorder sign-extends them, as a 64-bit call's are.
SIGNED_TYPES = {"int", "long", "pid_t", "off_t", "clockid_t", "timer_t", "mqd_t", "key_t",
                "key_serial_t", "rwf_t", "__s32"}
# Native code that reads arch-sized objects behind a value (ioctl and fcntl
# commands, prctl options, clone's and ptrace's registers, socket options,
# seccomp's sock_fprog, io_uring's iovecs): never translated. The recorder
# itself captures prctl's options of one layout (the task name) natively.
NOT_NATIVE = {"ioctl", "fcntl", "fcntl64", "prctl", "clone", "ptrace", "setsockopt", "getsockopt",
              "seccomp", "io_uring_enter", "io_uring_register"}
EXEC_CALLS = {"execve", "execveat"}


def native_counterparts(rows, native_table):
    """Each arm row's native aarch64 number, or None, and its signed mask."""
    native = {row["name"]: row for row in json.loads(native_table.read_text())["syscalls"]}
    result = {}
    for row in rows:
        signed = sum(1 << index for index, arg in enumerate(row["arguments"])
                     if not arg["pointer"] and arg["c_type"] in SIGNED_TYPES)
        twin = native.get(row.get("family", row["name"]))
        number = None
        if twin and row["name"] not in NOT_NATIVE and twin["arg_count"] is not None:
            own = [(arg["name"], arg["pointer"]) for arg in row["arguments"]]
            theirs = [(arg["name"], arg["pointer"]) for arg in twin["arguments"]]
            pointers_alike = all(not arg["pointer"] or arg["c_type"] in SAME_LAYOUT_POINTERS
                                 for arg in row["arguments"])
            if own == theirs[:len(own)] and (pointers_alike or row["name"] in EXEC_CALLS):
                number = twin["number"]
        result[row["number"]] = (number, signed)
    return result


def register_slots(row):
    """A 32-bit row's arguments as the registers its records carry."""
    slots = []
    for arg in row["arguments"]:
        if arg["pointer"] or arg["c_type"] not in WIDE_TYPES:
            slots.append(arg)
            continue
        if len(slots) % 2:
            slots.append({"name": "pad", "c_type": "u32", "pointer": False, "flags": None})
        for half in ("lo", "hi"):
            slots.append({"name": f"{arg['name']}_{half}", "c_type": "u32", "pointer": False,
                          "flags": None})
    if len(slots) > 6:
        raise ValueError(f"more than six argument registers: {row['name']}")
    return slots


def families(rows, family_table):
    """Name each arm row's x86-64 family, checking its arguments line up."""
    by_name = {row["name"]: row for row in json.loads(family_table.read_text())["syscalls"]}
    for row in rows:
        family = ARM_FAMILIES.get(row["name"])
        if family is None:
            continue
        own = [arg["name"] for arg in row["arguments"]]
        theirs = [arg["name"] for arg in by_name[family]["arguments"]]
        skip = ARM_FAMILY_DIFFERENCES.get(row["name"], set())
        if len(own) > len(theirs) or any(
                a != b for index, (a, b) in enumerate(zip(own, theirs)) if index not in skip):
            raise ValueError(f"{row['name']} does not line up with {family}: {own} {theirs}")
        row["family"] = family


def native_table(kernel, arch):
    version = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\d+)\s*$",
                             (kernel / "Makefile").read_text(), re.M))
    if [version.get(key) for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL")] != ["6", "12", "94"]:
        raise ValueError("native metadata requires the pinned Linux 6.12.94 tree")
    rows = []
    spec = ARCHES[arch]
    table = kernel / spec["table"]
    for line in table.read_text().splitlines():
        columns = line.partition("#")[0].split()
        if len(columns) < 3 or columns[1] not in spec["abis"]:
            continue
        rows.append({"number": int(columns[0]), "abi": columns[1],
                     "name": columns[2],
                     "entry_point": columns[3] if len(columns) > 3 else None})
    if len(rows) != spec["count"] or len({r["number"] for r in rows}) != len(rows):
        raise ValueError("pinned native syscall table changed; review the baseline")
    return table, rows


def pointer_aliases(kernel):
    header = kernel / "include/uapi/linux/capability.h"
    source = re.sub(r"^\s*#\s*include[^\n]*", "", header.read_text(), flags=re.M)
    source = "#define __user\ntypedef unsigned int __u32, __le32;\n" + source
    unit = cindex.Index.create().parse("native-aliases.c", args=["-std=gnu11"],
                                      unsaved_files=[("native-aliases.c", source)])
    if any(d.severity >= cindex.Diagnostic.Error for d in unit.diagnostics):
        raise ValueError("cannot parse pinned capability pointer aliases")
    aliases = {node.spelling for node in unit.cursor.get_children()
               if node.kind == cindex.CursorKind.TYPEDEF_DECL
               and node.underlying_typedef_type.get_canonical().kind == cindex.TypeKind.POINTER}
    if aliases != {"cap_user_header_t", "cap_user_data_t"}:
        raise ValueError("pinned capability aliases changed; review metadata")
    return aliases


def declarations(kernel, arch):
    header = kernel / "include/linux/syscalls.h"
    text = COMMENT.sub("", header.read_text())
    text = re.sub(r"^\s*#\s*include[^\n]*", "", text, flags=re.M)
    text = subprocess.run(
        ["cc", "-E", "-P", "-x", "c", f"-DBITS_PER_LONG={ARCHES[arch].get('bits', 64)}",
         *ARCHES[arch]["defines"], "-D__ARCH_WANT_SYS_UTIME=1", "-"], input=text, text=True,
        check=True, capture_output=True).stdout
    signatures = [(name, re.sub(r"\b__(?:user|force|kernel|iomem)\b", "", args))
                  for name, args in DECLARATION.findall(text)]
    # Typedef placeholders let Clang parse grammar without the full build's
    # include/config context. Their sizes are deliberately not exported.
    aliases = set()
    extra = re.findall(r"long\s+(sys_\w+)\s*\((.*?)\)\s*;", ARCHES[arch].get("declarations", ""), re.S)
    for _, args in signatures + extra:
        for arg in args.split(","):
            words = re.findall(r"\b[A-Za-z_]\w*\b", arg)
            if words == ["void"]:
                continue
            type_words = words[:-1]
            skip_tag = False
            for word in type_words:
                if skip_tag:
                    skip_tag = False
                elif word in ("struct", "union", "enum"):
                    skip_tag = True
                elif word not in KEYWORDS:
                    aliases.add(word)
    pointers = pointer_aliases(kernel)
    prelude = "\n".join(f"typedef {'void *' if name in pointers else 'unsigned long '}{name};"
                        for name in sorted(aliases))
    source = prelude + "\n" + "\n".join(
        f"long {name}({args});" for name, args in signatures) + ARCH_DECLARATIONS
    source += ARCHES[arch].get("declarations", "")
    unit = cindex.Index.create().parse(
        "native-declarations.c", args=["-std=gnu11", "-ferror-limit=0"],
        unsaved_files=[("native-declarations.c", source)])
    errors = [str(d) for d in unit.diagnostics if d.severity >= cindex.Diagnostic.Error]
    if errors:
        raise ValueError("native declaration parse failed:\n" + "\n".join(errors))
    parsed = {}
    for function in unit.cursor.get_children():
        if function.kind != cindex.CursorKind.FUNCTION_DECL:
            continue
        arguments = []
        for index, arg in enumerate(function.get_arguments()):
            spelling = arg.type.spelling
            arguments.append({"name": arg.spelling or f"arg{index}",
                              "c_type": spelling,
                              "pointer": arg.type.get_canonical().kind == cindex.TypeKind.POINTER,
                              "flags": None})
        if len(arguments) > 6:
            raise ValueError(f"more than six native arguments: {function.spelling}")
        parsed[function.spelling] = arguments
    return header, parsed


def flags_for(name, index, arg):
    groups = {
        ("open", 1): "open", ("openat", 2): "open",
        ("mmap", 2): "protection", ("mmap", 3): "mmap",
        ("mprotect", 2): "protection", ("pkey_mprotect", 2): "protection",
        ("clone", 0): "clone", ("socket", 1): "socket_type",
        ("socketpair", 1): "socket_type",
        ("sendto", 3): "message", ("recvfrom", 3): "message",
        ("sendmsg", 2): "message", ("recvmsg", 2): "message",
        ("sendmmsg", 3): "message", ("recvmmsg", 3): "message",
        ("accept4", 3): "accept", ("dup3", 2): "cloexec",
        ("epoll_create1", 0): "cloexec", ("eventfd2", 1): "eventfd",
        ("signalfd4", 3): "descriptor", ("inotify_init1", 0): "descriptor",
        ("pipe2", 1): "pipe", ("timerfd_create", 1): "descriptor",
        ("execveat", 4): "execveat", ("unlinkat", 2): "unlinkat",
        ("renameat2", 4): "rename", ("faccessat2", 3): "accessat",
        ("newfstatat", 3): "statat", ("statx", 2): "statx",
        ("getrandom", 2): "random", ("memfd_create", 1): "memfd",
        ("futex", 1): "futex", ("io_uring_enter", 3): "uring_enter",
        ("splice", 5): "splice", ("tee", 3): "splice",
        ("vmsplice", 3): "splice", ("mremap", 3): "mremap",
        ("flock", 1): "flock", ("mount", 3): "mount",
        ("umount2", 1): "unmount", ("unshare", 0): "clone_flags",
        ("linkat", 4): "linkat", ("fchmodat2", 3): "nofollow_empty",
        ("mlockall", 0): "mlockall", ("mlock2", 2): "mlock",
        ("futex_waitv", 2): "futex_waitv",
        ("futex_wake", 3): "futex2", ("futex_wait", 3): "futex2",
        ("futex_requeue", 1): "futex_requeue",
        ("io_uring_setup", 1): None,
        ("open_tree", 2): "open_tree", ("move_mount", 4): "move_mount",
        ("fsopen", 1): "fsopen", ("fspick", 2): "fspick",
        ("fsmount", 1): "fsopen", ("close_range", 2): "close_range",
        ("pidfd_open", 1): "pidfd_open", ("pidfd_send_signal", 3): "pidfd_signal",
        ("waitid", 3): "waitid", ("wait4", 2): "wait4",
        ("getxattr", 0): None, ("setxattr", 4): "xattr",
        ("lsetxattr", 4): "xattr", ("fsetxattr", 4): "xattr",
        ("utimensat", 3): "nofollow_empty", ("fchownat", 4): "nofollow_empty",
        ("fallocate", 1): "fallocate", ("sync_file_range", 3): "sync_range",
        ("preadv2", 5): "rwf", ("pwritev2", 5): "rwf",
        ("rseq", 2): "rseq", ("membarrier", 1): "membarrier_flags",
        ("msync", 2): "msync", ("clock_nanosleep", 1): "timer",
        ("timer_settime", 1): "timer", ("timerfd_settime", 1): "timerfd_settime",
        ("shmget", 2): "shmget", ("shmat", 2): "shmat",
        ("semget", 2): "ipc_create", ("msgget", 1): "ipc_create",
        ("msgsnd", 3): "msgsnd", ("msgrcv", 4): "msgrcv",
        ("delete_module", 1): "module_delete", ("finit_module", 2): "module_init",
        ("mbind", 5): "mbind", ("move_pages", 5): "mbind",
        ("get_mempolicy", 4): "mempolicy_get",
        ("perf_event_open", 4): "perf", ("seccomp", 1): "seccomp",
        ("userfaultfd", 0): "userfaultfd",
        ("open_by_handle_at", 2): "open", ("fanotify_init", 1): "open",
        ("name_to_handle_at", 4): "handle_at",
        ("mount_setattr", 2): "mount_setattr",
        ("landlock_create_ruleset", 2): "landlock_create",
        ("map_shadow_stack", 2): "shadow_stack", ("listmount", 3): "listmount",
        ("lsm_get_self_attr", 3): "lsm_get",
        ("fanotify_init", 0): "fanotify_init", ("fanotify_mark", 1): "fanotify_mark",
        ("kexec_load", 3): "kexec", ("kexec_file_load", 4): "kexec_file",
        # arm's own spellings.
        ("mmap2", 2): "protection", ("mmap2", 3): "mmap", ("fstatat64", 3): "statat",
        ("send", 3): "message", ("recv", 3): "message", ("arm_sync_file_range", 1): "sync_range",
    }
    return groups.get((name, index), "unknown" if arg["name"] in ("flags", "flag") else None)


def generate(kernel, arch, output, c_header):
    table, rows = native_table(kernel, arch)
    header, prototypes = declarations(kernel, arch)
    missing = []
    for row in rows:
        entry = row["entry_point"]
        arguments = prototypes.get(entry) if entry != "sys_ni_syscall" else None
        if entry and entry != "sys_ni_syscall" and arguments is None:
            missing.append(f"{row['number']} {row['name']} ({entry})")
        row["arguments"] = arguments or []
        # No table entry point, or the kernel's ENOSYS stub: never implemented here.
        row["implemented"] = bool(entry) and entry != "sys_ni_syscall"
        row["arg_count"] = len(arguments) if arguments is not None else None
        named = ARGUMENT_NAMES.get(row["name"])
        if row["name"] == "clone" and ARCHES[arch].get("clone_backwards"):
            named = CLONE_BACKWARDS_NAMES
        if named:
            source, names = named
            if len(names) != len(row["arguments"]):
                raise ValueError(f"native argument count mismatch: {row['name']}")
            for arg, name in zip(row["arguments"], names):
                arg["name"] = name
            row["argument_names_source"] = source
        if ARCHES[arch].get("bits") == 32:
            row["arguments"] = register_slots(row)
            row["arg_count"] = len(row["arguments"]) if arguments is not None else None
        for index, arg in enumerate(row["arguments"]):
            arg["flags"] = flags_for(row["name"], index, arg)
    if missing:
        raise ValueError("unresolved native prototypes:\n" + "\n".join(missing))
    table_rows = list(rows)
    if arch == "arm":
        families(rows, ROOT / "src/antinomie/monitor/protocol/x86_64/native-syscalls.json")
        # The aarch64 call the recorder captures an AArch32 call as: the
        # host reads those fields with aarch64's layouts and number.
        twins = native_counterparts(rows, ROOT / "src/antinomie/monitor/protocol/aarch64/native-syscalls.json")
        for row in rows:
            if twins[row["number"]][0] is not None:
                row["native"] = twins[row["number"]][0]
        for number, name, arguments in ARM_PRIVATE:
            rows.append({"number": number, "abi": "private", "name": name,
                         "entry_point": "arm_syscall",
                         "arguments": [{"name": arg, "c_type": c_type, "pointer": False,
                                        "flags": None} for arg, c_type in arguments],
                         "implemented": True, "arg_count": len(arguments)})
    document = {
        "kernel_version": "6.12.94", "architecture": arch,
        "schema_revision": 1, "native_count": len(table_rows),
        "provenance": {"table": str(table.relative_to(kernel)),
                       "table_sha256": hashlib.sha256(table.read_bytes()).hexdigest(),
                       "declarations": str(header.relative_to(kernel)),
                       "declarations_sha256": hashlib.sha256(header.read_bytes()).hexdigest(),
                       "pointer_aliases": "include/uapi/linux/capability.h",
                       "pointer_aliases_sha256": hashlib.sha256(
                           (kernel / "include/uapi/linux/capability.h").read_bytes()).hexdigest(),
                       "note": "Prototype facts only; no ABI sizes or pointer extent guesses"},
        "syscalls": rows,
    }
    text = json.dumps(document, indent=2) + "\n"
    output.write_text(text)
    # The guest reports this id in ARCH_INFO; the host compares it with the
    # SHA-256 of the protocol file it loaded for the guest's architecture.
    table_id = hashlib.sha256(text.encode()).hexdigest()
    size = table_rows[-1]["number"] + 1
    if ARCHES[arch].get("compat"):
        # Another architecture's compat table: the same entries under compat
        # names, included after that architecture's native table.
        lines = ["/* SPDX-License-Identifier: GPL-2.0-only */",
                 f"/* Generated declaration facts of the {arch} compat ABI"
                 " (scripts/generate-native-syscalls.py); do not hand-edit. */",
                 "#ifndef _ASM_ANTINOMIE_COMPAT_SYSCALLS_H", "#define _ASM_ANTINOMIE_COMPAT_SYSCALLS_H",
                 f"/* SHA-256 of protocol/{arch}/native-syscalls.json. */",
                 f'#define ANT_COMPAT_TABLE_ID "{table_id}"',
                 f"static const struct ant_native_syscall ant_compat_syscalls[{size}] = {{"]
    else:
        lines = ["/* SPDX-License-Identifier: GPL-2.0-only */",
                 f"/* Generated native declaration facts of {arch}"
                 " (scripts/generate-native-syscalls.py); do not hand-edit. */",
                 "#ifndef _ASM_ANTINOMIE_SYSCALLS_H", "#define _ASM_ANTINOMIE_SYSCALLS_H",
                 f"/* SHA-256 of protocol/{arch}/native-syscalls.json (ARCH_INFO). */",
                 f'#define ANT_NATIVE_TABLE_ID "{table_id}"',
                 "struct ant_native_syscall {", "\tu8 valid, argc, pointer_mask, string_mask;",
                 "\tconst char *name;", "\tconst char *argument_names[6];",
                 "\tconst char *argument_types[6];", "};",
                 f"static const struct ant_native_syscall ant_native_syscalls[{size}] = {{"]
    for row in table_rows:
        args = row["arguments"]
        pointer_mask = sum(1 << index for index, arg in enumerate(args) if arg["pointer"])
        string_mask = sum(1 << index for index, arg in enumerate(args)
                          if arg["pointer"] and "char" in arg["c_type"]
                          and arg["name"] in ("filename", "pathname", "path", "name",
                                               "oldname", "newname", "old", "new", "description"))
        count = row["arg_count"] if row["arg_count"] is not None else 255
        lines.append(f"\t[{row['number']}] = {{ 1, {count}, {pointer_mask}, {string_mask}, "
                     f"{json.dumps(row['name'])},")
        for key in ("name", "c_type"):
            lines.append("\t\t{")
            lines.extend(f"\t\t\t{json.dumps(arg[key])}," for arg in args)
            if not args:
                lines.append("\t\t\tNULL,")
            lines.append("\t\t},")
        lines.append("\t},")
    lines.append("};")
    if ARCHES[arch].get("compat"):
        twins = native_counterparts(table_rows,
                                    ROOT / "src/antinomie/monitor/protocol/aarch64/native-syscalls.json")
        assert all(twins[row["number"]][0] == row.get("native") for row in table_rows)
        lines.extend(["/* Each call's native counterpart (number + 1; 0: none, recorded by its",
                      " * registers only) and the arguments of 32-bit signed types. */",
                      "struct ant_compat_syscall {", "\tu16 native;", "\tu8 signed_mask;", "};",
                      f"static const struct ant_compat_syscall ant_compat_natives[{size}] = {{"])
        for number, (twin, signed) in sorted(twins.items()):
            if twin is not None or signed:
                lines.append(f"\t[{number}] = {{ {0 if twin is None else twin + 1}, {signed} }},")
        lines.append("};")
        print(f"compat: {sum(t is not None for t, _ in twins.values())} calls captured natively")
    lines.extend(["#endif", ""])
    rendered = "\n".join(lines)
    if not c_header.exists() or c_header.read_text() != rendered:
        c_header.write_text(rendered)
    print(f"generated {len(rows)} native entries, {sum(r['arg_count'] is None for r in rows)} historical placeholders")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=KERNEL)
    parser.add_argument("--arch", choices=sorted(ARCHES), default="x86_64")
    parser.add_argument("--output", type=Path,
                        help="default: protocol/<arch>/native-syscalls.json")
    parser.add_argument("--c-header", type=Path,
                        help="default: the arch's header in the kernel tree")
    args = parser.parse_args()
    output = args.output or ROOT / "src/antinomie/monitor/protocol" / args.arch / "native-syscalls.json"
    output.parent.mkdir(exist_ok=True)
    generate(args.kernel, args.arch, output,
             args.c_header or args.kernel / ARCHES[args.arch]["c_header"])


if __name__ == "__main__":
    main()
