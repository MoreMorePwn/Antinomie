#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Check a recording of tests/monitor/compat-calls-fixture.c.

The input is the text `event-dump RUN_DIR` prints for the run. Every compat
structure the recorder captures by its ILP32 layout (contract revision 21,
guest patches 49, 50 and 51) must be in it, COMPLETE, with the bytes and sizes
the fixture's calls produce, and none of those calls may keep a pointer that
is recorded by address only (NO_DECODER).

usage: compat-calls-check.py --abi ia32|arm EVENTS.txt
"""
import argparse
import re
import sys

EVENT = re.compile(r"^(\d+) pid (\d+) tid (\d+) (\S+) call (\d+) phase (\d+) ")
FIELD = re.compile(r"^    (\S+) status (\S+?)(?: \([^)]*\))? logical (\S+) captured (\d+) "
                   r"complete (true|false) \".*\" ([0-9a-f]*)$")
NO_DECODER = "Some(4)"
COMPLETE = "Some(0)"
TEXT = "compat-msg".encode().hex()

# (call, phase, key, bytes captured or None, preview prefix or "").
COMMON = [
    ("nanosleep", 1, "arg0.data", 8, "00000000"),
    ("clock_gettime", 2, "arg1.time", 8, ""),
    ("clock_getres", 2, "arg1.time", 8, ""),
    ("gettimeofday", 2, "arg0.time", 8, ""),
    ("rt_sigaction", 1, "arg1.action", 20, "01000000"),
    ("rt_sigaction", 2, "arg2.old_action", 20, ""),
    ("writev", 1, "arg1.iov", 8, ""),
    ("writev", 1, "arg1.iov[0].data", 6, "compat".encode().hex()),
    ("readv", 2, "arg1.iov[0].data", 6, "compat".encode().hex()),
    ("_newselect", 2, "arg1.fdset", 4, ""),
    ("getdents", 2, "arg1.dirents", None, ""),
    ("wait4", 2, "arg1.status", 4, "00050000"),
    ("stat64", 1, "arg0.path", None, ""),
    ("lstat64", 1, "arg0.path", None, ""),
    ("fstatat64", 1, "arg1.path", None, ""),
    ("stat", 1, "arg0.path", None, ""),
    ("stat", 2, "arg1.statbuf", 64, ""),
    ("lstat", 2, "arg1.statbuf", 64, ""),
    ("fstat", 2, "arg1.statbuf", 64, ""),
    ("statfs", 1, "arg0.path", None, ""),
    ("statfs", 2, "arg1.buf", 64, ""),
    ("fstatfs", 2, "arg1.buf", 64, ""),
    ("statfs64", 1, "arg0.path", None, ""),
    ("statfs64", 2, "arg2.buf", 84, ""),
    ("fstatfs64", 2, "arg2.buf", 84, ""),
    ("getitimer", 2, "arg1.value", 16, ""),
    ("setitimer", 1, "arg1.value", 16, "00" * 16),
    ("setitimer", 2, "arg2.ovalue", 16, ""),
    ("waitid", 2, "arg2.infop", 128, "11000000"),
    ("waitid", 2, "arg4.ru", 72, ""),
    ("sendmsg", 1, "arg1.msghdr", 28, ""),
    ("sendmsg", 1, "arg1.msghdr.iov", 8, ""),
    ("sendmsg", 1, "arg1.msghdr.iov[0].data", 10, TEXT),
    ("sendmsg", 1, "arg1.msghdr.name", 16, "0200"),
    ("sendmsg", 1, "arg1.msghdr.control", 16, "10000000"),
    ("recvmsg", 1, "arg1.msghdr", 28, ""),
    ("recvmsg", 1, "arg1.msghdr.iov", 8, ""),
    ("recvmsg", 2, "arg1.msghdr.output", 28, ""),
    ("recvmsg", 2, "arg1.msghdr.iov[0].data", 10, TEXT),
    ("recvmsg", 2, "arg1.msghdr.name", 16, "0200"),
    ("recvmsg", 2, "arg1.msghdr.control", 16, "10000000"),
    ("sendmmsg", 1, "arg1.mmsg.0.header", 28, ""),
    ("sendmmsg", 1, "arg1.mmsg.1.iov[0].data", 3, "msg".encode().hex()),
    ("sendmmsg", 1, "arg1.mmsg.1.name", 16, "0200"),
    ("sendmmsg", 2, "arg1.mmsg.1.header", 32, ""),
    ("recvmmsg", 1, "arg1.mmsg.1.iov", 8, ""),
    ("recvmmsg", 1, "arg4.timeout", 8, "01000000"),
    ("recvmmsg", 2, "arg1.mmsg.1.header", 32, ""),
    ("recvmmsg", 2, "arg1.mmsg.0.iov[0].data", 6, "compat".encode().hex()),
    ("recvmmsg", 2, "arg1.mmsg.1.iov[0].data", 3, "msg".encode().hex()),
    ("recvmmsg", 2, "arg4.timeout.observed", 8, ""),
    ("recvmmsg_time64", 1, "arg4.timeout", 16, "0100000000000000"),
    ("recvmmsg_time64", 2, "arg1.mmsg.0.iov[0].data", 6, "compat".encode().hex()),
]
# struct stat64: 96 bytes on i386 (packed), 104 on ARM EABI.
STAT64 = {"ia32": 96, "arm": 104}
STAT64_CALLS = [("stat64", "arg1.statbuf"), ("lstat64", "arg1.statbuf"),
                ("fstat64", "arg1.statbuf"), ("fstatat64", "arg2.statbuf")]
# poll: ia32's pollfd is x86-64's, so its native twin captures it (key
# arg0.pollfd); AArch32's goes through the compat rules (arg0.pollfds).
POLL = {"ia32": ("poll", 1, "arg0.pollfd", 8, "03000000"),
        "arm": ("poll", 1, "arg0.pollfds", 8, "03000000")}
# Patch 51: futex's 32-bit timeout (futex_time64 is the native call's twin,
# with the native 16-byte timeout) and the SysV IPC control records.
COMMON += [
    ("futex", 1, "arg0.futex.observed", 4, "07000000"),
    ("futex", 1, "arg3.timeout", 8, "00000000e8030000"),
    ("futex", 1, "arg4.futex.observed", 4, "09000000"),
    ("futex_time64", 1, "arg3.timeout", 16, "0000000000000000e803000000000000"),
    # IPC_64 records: compat_msqid64_ds, compat_shmid64_ds, compat_semid64_ds,
    # compat_shminfo64; the IPC_SET input; msginfo, shm_info, seminfo.
    ("msgctl", 2, "ipc.control", 88, ""),
    ("msgctl", 1, "ipc.control", 88, ""),
    ("msgctl", 2, "ipc.control", 32, ""),
    ("shmctl", 2, "ipc.control", 84, ""),
    ("shmctl", 2, "ipc.control", 36, ""),
    ("shmctl", 2, "ipc.control", 24, ""),
    ("semctl", 2, "ipc.control", 64, ""),
    ("semctl", 2, "ipc.control", 40, ""),
]
# epoll_wait and epoll_pwait: ia32's epoll_event is x86-64's (12 bytes,
# packed), so the native twins capture them (sigmask as signal.mask); AArch32's
# (16 bytes) go through the compat capture.
EPOLL = {"ia32": [("epoll_wait", 2, "arg1.epoll_events", 12, "01000000"),
                  ("epoll_pwait", 2, "arg1.epoll_events", 12, "01000000"),
                  ("epoll_pwait", 1, "signal.mask", 8, "")],
         "arm": [("epoll_wait", 2, "arg1.epoll_events", 16, "0100000000000000"),
                 ("epoll_pwait", 2, "arg1.epoll_events", 16, "0100000000000000"),
                 ("epoll_pwait", 1, "arg4.sigmask", 8, "")]}
# The old records without IPC_64: AArch32's direct calls (old_msgctl and the
# others) and ia32's ipc(); ia32's direct calls copy the IPC_64 ones always.
IPC_OLD = {"ia32": [("ipc", 2, "ipc.control", 56, ""), ("ipc", 2, "ipc.control", 88, ""),
                    ("ipc", 2, "ipc.control", 48, ""), ("ipc", 2, "ipc.control", 64, ""),
                    ("ipc", 2, "ipc.control", 44, "")],
           "arm": [("msgctl", 2, "ipc.control", 56, ""), ("shmctl", 2, "ipc.control", 48, ""),
                   ("semctl", 2, "ipc.control", 44, "")]}
CALLS = ({name for name, *_ in COMMON} | {name for name, _ in STAT64_CALLS}
         | {"epoll_wait", "epoll_pwait", "ipc"})


def parse(text):
    """The last view of every event: (call, phase, {key: field}), in order."""
    events = {}
    current = None
    for line in text.splitlines():
        match = EVENT.match(line)
        if match:
            current = {"call": match.group(4), "phase": int(match.group(6)), "fields": {}}
            events[int(match.group(1))] = current
            continue
        match = FIELD.match(line)
        if match and current is not None:
            current["fields"][match.group(1)] = {
                "status": match.group(2), "captured": int(match.group(4)),
                "complete": match.group(5) == "true", "hex": match.group(6)}
    return [events[seq] for seq in sorted(events)]


def check(events, abi):
    """Problems, one line each; empty when the recording is right."""
    problems = []
    expected = list(COMMON) + [POLL[abi]] + EPOLL[abi] + IPC_OLD[abi] + [
        (call, 2, key, STAT64[abi], "") for call, key in STAT64_CALLS]
    for call, phase, key, size, prefix in expected:
        found = [event["fields"].get(key) for event in events
                 if event["call"] == call and event["phase"] == phase]
        found = [field for field in found if field]
        good = [field for field in found if field["status"] == COMPLETE and field["complete"]
                and (size is None or field["captured"] == size)
                and field["hex"].startswith(prefix)]
        if not good:
            problems.append(f"{call} phase {phase} {key}: "
                            + (f"recorded as {found}" if found else "not recorded")
                            + f", wanted COMPLETE{'' if size is None else f' {size} bytes'}"
                            + (f" starting {prefix}" if prefix else ""))
    for event in events:
        if event["call"] not in CALLS:
            continue
        for key, field in event["fields"].items():
            if field["status"] == NO_DECODER:
                problems.append(f"{event['call']} phase {event['phase']} {key}: NO_DECODER")
    if abi == "ia32":
        through = [event for event in events if event["call"] in ("sendmsg", "recvmsg")
                   and "socketcall.call" in event["fields"]
                   and "arg1.msghdr" in event["fields"]]
        if len({event["call"] for event in through}) < 2:
            problems.append("socketcall sendmsg/recvmsg: no msghdr recorded through socketcall")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--abi", choices=sorted(STAT64), required=True)
    parser.add_argument("events", help="event-dump output of the fixture's run")
    options = parser.parse_args()
    with open(options.events, encoding="utf-8", errors="replace") as handle:
        events = parse(handle.read())
    problems = check(events, options.abi)
    for problem in problems:
        print("FAIL", problem)
    print(f"{'PASS' if not problems else 'FAIL'} compat calls ({options.abi}): "
          f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
