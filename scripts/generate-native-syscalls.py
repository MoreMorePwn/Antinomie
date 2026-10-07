#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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
# SYSCALL_DEFINE declarations (clone uses the normal x86-64 ordering).
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
}


def native_table(kernel):
    version = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\d+)\s*$",
                             (kernel / "Makefile").read_text(), re.M))
    if [version.get(key) for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL")] != ["6", "12", "94"]:
        raise ValueError("native metadata requires the pinned Linux 6.12.94 tree")
    rows = []
    table = kernel / "arch/x86/entry/syscalls/syscall_64.tbl"
    for line in table.read_text().splitlines():
        columns = line.partition("#")[0].split()
        if len(columns) < 3 or columns[1] not in ("common", "64"):
            continue
        rows.append({"number": int(columns[0]), "abi": columns[1],
                     "name": columns[2],
                     "entry_point": columns[3] if len(columns) > 3 else None})
    if len(rows) != 375 or len({r["number"] for r in rows}) != len(rows):
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


def declarations(kernel):
    header = kernel / "include/linux/syscalls.h"
    text = COMMENT.sub("", header.read_text())
    text = re.sub(r"^\s*#\s*include[^\n]*", "", text, flags=re.M)
    text = subprocess.run(
        ["cc", "-E", "-P", "-x", "c", "-DBITS_PER_LONG=64",
         "-DCONFIG_X86_64=1", "-D__ARCH_WANT_SYS_UTIME=1", "-"], input=text, text=True,
        check=True, capture_output=True).stdout
    signatures = [(name, re.sub(r"\b__(?:user|force|kernel|iomem)\b", "", args))
                  for name, args in DECLARATION.findall(text)]
    # Typedef placeholders let Clang parse grammar without the full build's
    # include/config context. Their sizes are deliberately not exported.
    aliases = set()
    for _, args in signatures:
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
    }
    return groups.get((name, index), "unknown" if arg["name"] in ("flags", "flag") else None)


def generate(kernel, output, c_header):
    table, rows = native_table(kernel)
    header, prototypes = declarations(kernel)
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
        if row["name"] in ARGUMENT_NAMES:
            source, names = ARGUMENT_NAMES[row["name"]]
            if len(names) != len(row["arguments"]):
                raise ValueError(f"native argument count mismatch: {row['name']}")
            for arg, name in zip(row["arguments"], names):
                arg["name"] = name
            row["argument_names_source"] = source
        for index, arg in enumerate(row["arguments"]):
            arg["flags"] = flags_for(row["name"], index, arg)
    if missing:
        raise ValueError("unresolved native prototypes:\n" + "\n".join(missing))
    document = {
        "kernel_version": "6.12.94", "architecture": "x86_64",
        "schema_revision": 1, "native_count": len(rows),
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
    output.write_text(json.dumps(document, indent=2) + "\n")
    lines = ["/* SPDX-License-Identifier: GPL-2.0-only */",
             "/* Generated native declaration facts; do not hand-edit. */",
             "#ifndef ANTINOMIE_NATIVE_SYSCALLS_H", "#define ANTINOMIE_NATIVE_SYSCALLS_H",
             "struct ant_native_syscall {", "\tu8 valid, argc, pointer_mask, string_mask;",
             "\tconst char *name;", "\tconst char *argument_names[6];",
             "\tconst char *argument_types[6];", "};",
             f"static const struct ant_native_syscall ant_native_syscalls[{rows[-1]['number'] + 1}] = {{"]
    for row in rows:
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
    lines.extend(["};", "#endif", ""])
    rendered = "\n".join(lines)
    if not c_header.exists() or c_header.read_text() != rendered:
        c_header.write_text(rendered)
    print(f"generated {len(rows)} native entries, {sum(r['arg_count'] is None for r in rows)} historical placeholders")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=KERNEL)
    parser.add_argument("--output", type=Path, default=ROOT / "src/antinomie/monitor/protocol/native-syscalls.json")
    parser.add_argument("--c-header", type=Path, default=KERNEL / "kernel/antinomie/native_syscalls.h")
    args = parser.parse_args()
    generate(args.kernel, args.output, args.c_header)


if __name__ == "__main__":
    main()
