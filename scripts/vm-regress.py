#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the VM regression checks in tiers, one VM at a time.

usage: vm-regress.py quick BASE [options]
       vm-regress.py full  BASE --old-base OLD [--old-host REV|PATH] [options]
       vm-regress.py auto  BASE [--against REF] [--old-base OLD] [...]

quick  the conformance trace suite's oracle groups (user, root, threads)
full   quick, the debugger, audit, io_uring, tracer, stealth and snapshot
       checks, the conformance stress groups and interop in both directions
       (an old host on BASE, the current host on OLD)
auto   full when the diff against REF touches the kernel/host contract (guest
       patches, transport, protocol docs, ANTC_REVISION), otherwise quick

BASE is a BusyBox base bundle built from the current guest series. Everything
a check writes goes under --out (default vm-regress-out): logs, runs, the
fixtures built from tests/monitor and private HOME and XDG folders per check.
The app's own data and settings are never used.
"""
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "src/antinomie/monitor"
EXAMPLES = Path("target/release/examples")
TESTS = ROOT / "tests/monitor"

# Changing any of these changes the contract between guest kernel and host.
CONTRACT_PATHS = (
    "src/antinomie/core/",
    "src/antinomie/patches/",
    "src/antinomie/transport/",
    "src/antinomie/monitor/protocol/",
)
# A changed line that sets the revision (control.h, control.rs).
REVISION_LINE = r"^[[:space:]]*(#[[:space:]]*define[[:space:]]+ANTC_REVISION[[:space:]]|(pub(\([a-z]+\))?[[:space:]]+)?const[[:space:]]+REVISION:)"

QUICK_GROUPS = "user,root,threads"
STRESS_GROUPS = ("stress-light", "stress-heavy", "stress-extreme", "stress-lossy")
MIN_MEM_KIB = 5 * 1024 * 1024
GIB = 1024**3
# What a finished check leaves that only matters for debugging it: VM disks and recordings.
CONFORMANCE_BULK = ("groups", "render", "bin", "xdg")
ORDER = ("PASS", "FLAKY", "FAIL", "TIMEOUT", "ERROR", "SKIP")


class Failure(Exception):
    pass


# Tiers and the auto decision


def contract_reasons(paths, revision_files=()):
    """Why a change touches the kernel/host contract: one line per cause."""
    reasons = []
    for path in sorted(set(paths)):
        for prefix in CONTRACT_PATHS:
            if path.startswith(prefix):
                reasons.append(f"{path} is under {prefix}")
                break
    for path in sorted(set(revision_files)):
        reasons.append(f"{path} changes ANTC_REVISION")
    return reasons


def choose_tier(paths, revision_files=()):
    reasons = contract_reasons(paths, revision_files)
    if reasons:
        return "full", reasons
    return "quick", [f"none of {len(set(paths))} changed paths is a contract path"]


def git(*args, check=True):
    done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    if check and done.returncode:
        raise Failure(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout


def default_against():
    """origin/ plus the release branch HEAD is closest to."""
    best = None
    for ref in git("for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/release-*").split():
        ahead = git("rev-list", "--count", f"{ref}..HEAD", check=False).strip()
        if ahead.isdigit():
            version = [int(part) for part in re.findall(r"\d+", ref)]
            key = (int(ahead), [-part for part in version])
            if best is None or key < best[0]:
                best = (key, ref)
    if best is None:
        raise Failure("no origin/release-* ref: name one with --against")
    return best[1]


def changed_against(ref):
    """Paths and revision-changing files of commits plus working tree since ref."""
    base = git("merge-base", ref, "HEAD").strip()
    paths = git("diff", "--name-only", base).split()
    paths += git("ls-files", "--others", "--exclude-standard").split()
    revision = git("diff", "--name-only", f"-G{REVISION_LINE}", base, "--").split()
    return paths, revision


# Disk space: WSL's Linux disk is a file on a Windows drive that only grows


def disk_problem(args):
    """Why a check must not start now (disk too full), or None."""
    used = shutil.disk_usage("/").used / GIB
    if used > args.max_used_gb:
        return f"Linux disk used {used:.0f} GiB is over the limit of {args.max_used_gb} GiB"
    for spec in args.min_free:
        path, _, limit = spec.rpartition(":")
        try:
            free = shutil.disk_usage(path).free / GIB
        except OSError as error:
            return f"--min-free {spec}: {error}"
        if free < float(limit):
            return f"{path} has {free:.1f} GiB free, under the limit of {limit} GiB"
    return None


def disk_guard(args):
    problem = disk_problem(args)
    if problem:
        raise Failure(f"disk: {problem}; clean up and rerun (--rerun-failed)")


def default_min_free():
    """On WSL the Windows drive behind the Linux disk must keep room."""
    try:
        wsl = "microsoft" in Path("/proc/version").read_text().lower()
    except OSError:
        wsl = False
    return ["/mnt/e:5"] if wsl and Path("/mnt/e").is_dir() else []


def safe_rmtree(path, root):
    """Remove path only when it really is below root: no link in the way, no escape.

    shutil.rmtree refuses only a link as the last component, so a linked parent
    (out/runs -> elsewhere) would be followed. A link as path itself is unlinked,
    never followed.
    """
    path, root = Path(path), Path(root)
    real_root = Path(os.path.realpath(root))
    try:
        rel = Path(os.path.abspath(path)).relative_to(os.path.abspath(root))
    except ValueError:
        raise Failure(f"refusing to remove {path}: not below {root}") from None
    if rel == Path("."):
        raise Failure(f"refusing to remove {root} itself")
    parent = Path(os.path.realpath(path.parent))
    if parent != real_root / rel.parent:
        raise Failure(f"refusing to remove {path}: a parent folder is a link leaving {root}")
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path, ignore_errors=True)


def clean_check_data(out, name):
    """Remove the VM disks, recordings and private folders a recorded check left."""
    runs = out / "runs" / name
    if name.startswith("conf-"):
        for bulk in CONFORMANCE_BULK:
            safe_rmtree(runs / bulk, out)
    else:
        safe_rmtree(runs, out)
    safe_rmtree(out / "xdg" / name, out)


# Environment and processes


def mem_available_kib():
    with open("/proc/meminfo") as meminfo:
        for line in meminfo:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    return 0


def memwait(minimum, limit):
    """Block until MemAvailable allows a boot; other agents boot VMs too."""
    start = time.monotonic()
    while mem_available_kib() < minimum:
        if time.monotonic() - start > limit:
            raise Failure(f"memory: MemAvailable stayed under {minimum // 1024 // 1024} GiB for {limit} s")
        print(f"  memwait: MemAvailable {mem_available_kib() // 1024} MiB, waiting", flush=True)
        time.sleep(20)


def stat_fields(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # comm is parenthesised and may contain spaces.
    head, _, tail = text.rpartition(")")
    return head.partition("(")[2], tail.split()


def descendants(pid):
    """(pid, start time) of every process below pid, found through /proc."""
    children = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            fields = stat_fields(int(entry.name))
            if fields:
                children.setdefault(int(fields[1][1]), []).append((int(entry.name), fields))
    found, todo = [], [pid]
    while todo:
        for child, fields in children.get(todo.pop(), []):
            if "sccache" not in fields[0]:
                found.append((child, fields[1][19]))
                todo.append(child)
    return found


def tree_members(pid):
    """(pid, start time) of pid's own tree: its descendants and what is left in its session.

    The child runs in a session of its own (start_new_session), so a grandchild
    re-parented to init after its parent died is still found by the session id.
    Nothing outside that session or that tree is ever listed.
    """
    found = dict(descendants(pid))
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            fields = stat_fields(int(entry.name))
            if fields and "sccache" not in fields[0] and fields[1][3] == str(pid):
                found[int(entry.name)] = fields[1][19]
    found.pop(pid, None)
    return sorted(found.items())


def alive(pid, started):
    fields = stat_fields(pid)
    return bool(fields) and fields[1][0] != "Z" and (started is None or fields[1][19] == started)


def stop_tree(process, grace=30):
    """End the child we started and what it started (a VM monitor), nothing else.

    The tree is listed again before every signal, and the wait covers every
    member, not only the child, so a descendant that outlives its parent still
    gets the KILL round.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        members = [(process.pid, None)] + tree_members(process.pid)
        for pid, started in members:
            if alive(pid, started):
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            members = [(process.pid, None)] + tree_members(process.pid)
            if process.poll() is not None and not any(alive(pid, started) for pid, started in members[1:]):
                break
            time.sleep(0.2)
        else:
            continue
        break
    process.wait()
    for pid, started in tree_members(process.pid):
        if alive(pid, started):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def run_logged(argv, env, cwd, log, timeout):
    """Run argv with its output in log; (exit code or None on timeout, seconds)."""
    start = time.monotonic()
    with open(log, "ab") as out:
        out.write(f"$ {' '.join(map(str, argv))}\n".encode())
        out.flush()
        process = subprocess.Popen(argv, env=env, cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop_tree(process)
            code = None
        except BaseException:
            stop_tree(process)
            raise
        out.write(f"EXIT {code if code is not None else 'timeout'}\n".encode())
    return code, time.monotonic() - start


def private_env(out, name):
    """HOME and XDG folders of one check, all under out; tools keep working."""
    real = Path(os.environ.get("HOME", "/nonexistent"))
    env = dict(os.environ)
    base = out / "xdg" / name
    for var, folder in (("HOME", "home"), ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                        ("XDG_CACHE_HOME", "cache"), ("XDG_STATE_HOME", "state")):
        (base / folder).mkdir(parents=True, exist_ok=True)
        env[var] = str(base / folder)
    # cargo-driven checks still need the toolchain and the compiler cache.
    for var, default in (("CARGO_HOME", real / ".cargo"), ("RUSTUP_HOME", real / ".rustup"),
                         ("SCCACHE_DIR", real / ".cache/sccache"), ("SCCACHE_CONF", real / ".config/sccache/config")):
        if var not in os.environ and default.exists():
            env[var] = str(default)
    for var in ("WAYLAND_DISPLAY", "DISPLAY"):
        env.pop(var, None)
    return env


# Checks


class Check:
    def __init__(self, name, group, argv, cwd, timeout, vm=True, needs=(), cargo=False):
        self.name, self.group, self.argv, self.cwd = name, group, argv, cwd
        self.timeout, self.vm, self.needs, self.cargo = timeout, vm, needs, cargo


def plan(tier, ctx):
    """The checks of a tier in run order. ctx holds paths: base, old_base, out, new, old, fix."""
    out, new, fix, base, old_base = ctx["out"], ctx["new"], ctx["fix"], ctx["base"], ctx["old_base"]
    runs = out / "runs"
    mon = str(MONITOR)

    def example(name, *args, ex=new):
        return [str(ex / name), *map(str, args)]

    checks = [Check("conf-quick", "quick",
                    example("conformance", "trace", base, runs / "conf-quick", "--groups", QUICK_GROUPS),
                    mon, 3600, needs=("base",))]
    if tier == "quick":
        return checks

    def vm_check(name, group, mode, args, bundle=base, ex=new, timeout=2400, needs=("base",), cwd=ROOT):
        return Check(name, group, example(mode, args[0], bundle, runs / name, *args[1:], ex=ex), str(cwd),
                     timeout, needs=needs)

    torture, urfix = fix / "ant-torture", fix / "uring-fixture"
    checks += [
        *[Check(f"conf-{group}", "full",
                example("conformance", "trace", base, runs / f"conf-{group}", "--groups", group),
                mon, 7200, needs=("base",)) for group in STRESS_GROUPS],
        vm_check("debug-p2", "full", "debug-check", ["p2", fix / "debug"]),
        vm_check("debug-p3", "full", "debug-check", ["p3", fix / "debug"]),
        vm_check("audit-stop", "full", "audit-check", ["stop", fix / "audit-fixture"]),
        vm_check("audit-core", "full", "audit-check", ["core", fix / "audit-fixture"]),
        vm_check("uring-status", "full", "uring-check", ["status", torture, urfix], timeout=3000),
        vm_check("uring-boots", "full", "uring-check", ["boots", torture, urfix], timeout=3000),
        vm_check("uring-legacy", "full", "uring-check", ["legacy", torture, urfix], bundle=old_base,
                 timeout=3000, needs=("old_base",)),
        vm_check("tracer-record", "full", "tracer-check", ["record", fix / "tracer-fixture"]),
        vm_check("tracer-legacy", "full", "tracer-check", ["legacy", fix / "tracer-fixture"], bundle=old_base,
                 needs=("old_base",)),
        Check("tracer-qa", "full", None, mon, 2400, vm=False, cargo=True),
        Check("debugger-live", "full", None, mon, 2400, cargo=True, needs=("base", "tools")),
        vm_check("stealth", "full", "stealth-check", ["measure", fix / "stealth-probe"]),
        Check("snapshot", "full", example("snapshot-check", base, runs / "snapshot"), str(ROOT), 2400,
              needs=("base",)),
    ]
    # Old host on the new base runs the whole contract; the new host on an old base can only
    # run what that guest has: the legacy checks above (io_uring, tracer) and the audit core.
    old, olds = ctx["old"], ctx["old_base"]
    interop = [
        ("io-old-new-stealth", "stealth-check", ["measure", fix / "stealth-probe"], base, old),
        ("io-old-new-uring", "uring-check", ["status", torture, urfix], base, old),
        ("io-old-new-tracer", "tracer-check", ["record", fix / "tracer-fixture"], base, old),
        ("io-old-new-audit", "audit-check", ["core", fix / "audit-fixture"], base, old),
        ("io-old-new-p3", "debug-check", ["p3", fix / "debug"], base, old),
        ("io-new-old-audit", "audit-check", ["core", fix / "audit-fixture"], olds, new),
    ]
    needs = ("base", "old_base", "old")
    for name, mode, args, bundle, ex in interop:
        checks.append(vm_check(name, "interop", mode, args, bundle=bundle, ex=ex,
                               timeout=3000 if "uring" in name else 2400, needs=needs))
    return checks


def select(checks, only, skip):
    names = {check.name for check in checks}
    for name in list(only) + list(skip):
        if name not in names:
            raise Failure(f"unknown check {name}; this tier has: {', '.join(sorted(names))}")
    return [c for c in checks if (not only or c.name in only) and c.name not in skip]


# Fixtures and hosts


def build_fixtures(out):
    """Static guest programs from tests/monitor, built once per output folder."""
    fix = out / "fixtures"
    stamp = fix / ".built"
    if stamp.exists():
        return fix
    log = out / "logs" / "fixtures.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    fix.mkdir(parents=True, exist_ok=True)
    (fix / "debug").mkdir(exist_ok=True)
    env = dict(os.environ)
    strict = ["-Wall", "-Wextra", "-Werror"]
    builds = [
        (["-static", "-O2", *strict], "audit-fixture.c", fix / "audit-fixture"),
        (["-static", "-O2", "-pthread", *strict], "uring-fixture.c", fix / "uring-fixture"),
        (["-static", "-O2", *strict], "tracer-fixture.c", fix / "tracer-fixture"),
        (["-static", "-O2", *strict], "stealth-probe.c", fix / "stealth-probe"),
        (["-O1", "-static", "-no-pie", "-pthread"], "debug-p2-fixture.c", fix / "debug/p2fix"),
        (["-O1", "-static-pie", "-pthread"], "debug-p2-fixture.c", fix / "debug/p2pie"),
        (["-O1", "-static", "-no-pie", "-pthread"], "debug-p3-fixture.c", fix / "debug/p3fix"),
        (["-O1", "-pthread", "-Wl,--dynamic-linker=/tmp/p2ld.so", "-Wl,-rpath,/tmp"],
         "debug-p2-fixture.c", fix / "debug/p2dyn"),
    ]
    for flags, source, target in builds:
        code, _ = run_logged(["gcc", *flags, "-o", str(target), str(TESTS / source)], env, str(ROOT), log, 600)
        if code != 0:
            raise Failure(f"building {source} failed, see {log}")
    # The dynamic debug fixture brings the host's loader and libc.
    root = fix / "debug/dbgroot"
    root.mkdir(exist_ok=True)
    libc = subprocess.run(["gcc", "-print-file-name=libc.so.6"], capture_output=True, text=True).stdout.strip()
    loader = subprocess.run(["gcc", "-print-file-name=ld-linux-x86-64.so.2"], capture_output=True, text=True).stdout.strip()
    for source, name in ((libc, "libc.so.6"), (loader, "p2ld.so")):
        if not Path(source).exists():
            raise Failure(f"no {name} source on this host ({source})")
        shutil.copy2(os.path.realpath(source), root / name)
    code, _ = run_logged([str(TESTS / "build-torture.sh"), str(fix), "--static"], env, str(ROOT), log, 1800)
    if code != 0:
        raise Failure(f"building the stress samples failed, see {log}")
    stamp.write_text("built\n")
    return fix


def build_examples(repo, out, log_name, app=False):
    log = out / "logs" / log_name
    log.parent.mkdir(parents=True, exist_ok=True)
    for extra in (["--examples"], ["-p", "antinomie-monitor-ui", "--bin", "antinomie-monitor"]) if app else (["--examples"],):
        code, _ = run_logged(["cargo", "build", "--release", "--locked", "-j", "2", *extra],
                             dict(os.environ), str(repo / "src/antinomie/monitor"), log, 7200)
        if code != 0:
            raise Failure(f"cargo build failed, see {log}")
    return repo / "src/antinomie/monitor" / EXAMPLES


def old_host(spec, out):
    """(examples folder, cleanup) of the old host: a built checkout or a git rev."""
    path = Path(spec).expanduser()
    if path.is_dir():
        for candidate in (path, path / "src/antinomie/monitor" / EXAMPLES, path / EXAMPLES):
            if (candidate / "debug-check").is_file():
                return candidate.resolve(), lambda: None
        raise Failure(f"{path} has no built examples (target/release/examples/debug-check)")
    tree = out / "old-host"
    log = out / "logs" / "old-host.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    git("worktree", "add", "--detach", str(tree), spec)

    def cleanup():
        git("worktree", "remove", "--force", str(tree), check=False)
        safe_rmtree(tree, out)
        git("worktree", "prune", check=False)

    try:
        return build_examples(tree, out, "old-host.log"), cleanup
    except BaseException:
        cleanup()
        raise


def tools_dir(args, out):
    """The managed gef and pwndbg the Debugger console check needs, in a private data folder."""
    data = out / "debugger-data"
    (data / "tools").mkdir(parents=True, exist_ok=True)
    source = Path(args.debugger_tools).expanduser() / "tools" if args.debugger_tools else None
    for tool in ("gef", "pwndbg"):
        destination = data / "tools" / tool
        complete = destination / ".vm-regress-copy-complete"
        if complete.is_file():
            continue
        if source and (source / tool).is_dir():
            # A previous interruption may have left only part of a tool. Never
            # publish that directory before the entire copy and stamp are ready.
            with tempfile.TemporaryDirectory(prefix=f".{tool}-", dir=data / "tools") as temporary:
                staged = Path(temporary) / tool
                shutil.copytree(source / tool, staged, symlinks=True)
                (staged / ".vm-regress-copy-complete").write_text("1\n")
                safe_rmtree(destination, data)
                staged.rename(destination)
    return data


# Running


def command_for(check, ctx, args):
    """The argv of the checks that need the previous results or a test filter."""
    if check.name == "debugger-live":
        env = {
            "ANTINOMIE_DEBUG_LIVE_BUNDLE": str(ctx["base"]),
            "ANTINOMIE_DEBUG_LIVE_DATA": str(ctx["debugger_data"]),
            "ANTINOMIE_DEBUG_LIVE_FIXTURE": str(ctx["fix"] / "debug/p2fix"),
        }
        argv = ["cargo", "test", "--release", "--locked", "-j", "2", "-p", "antinomie-monitor-ui", "--bin",
                "antinomie-monitor", "debugger_console_live", "--", "--ignored", "--nocapture"]
        return argv, env
    if check.name == "tracer-qa":
        # Triage QA over the recordings of a failed tracer-record would pass on
        # whatever that run left: its input must have passed.
        record = input_result(ctx, "tracer-record")
        if record is None:
            raise Failure("its input tracer-record has no result; run tracer-record first")
        if record["status"] not in ("PASS", "FLAKY"):
            raise Failure(f"its input tracer-record did not pass ({record['status']}, {record['log']})")
        log = Path(record["log"])
        text = log.read_text(errors="replace") if log.exists() else ""
        runs = re.findall(r"^RUN (.*)$", text, re.M)
        sha = re.search(r"^FIXTURE_SHA256 (\S+)", text, re.M)
        writes = re.search(r"^RUN writes=(.*?)/tracer_record_", text, re.M)
        if not (runs and sha and writes):
            raise Failure("no usable tracer-record log (RUN, FIXTURE_SHA256); run tracer-record first")
        if not Path(writes.group(1)).is_dir():
            raise Failure("tracer-record's data is gone (cleaned after its check); rerun it with --keep-data")
        env = {
            "ANTINOMIE_TRACER_RUNS": ";".join(runs) + ";",
            "ANTINOMIE_TRACER_FIXTURE_SHA256": sha.group(1),
            "ANTINOMIE_TRACER_DATA": writes.group(1),
            "ANTINOMIE_DISK_READER": str(MONITOR / "target/release/antinomie-monitor"),
        }
        argv = ["cargo", "test", "--release", "--locked", "-j", "2", "-p", "antinomie-monitor-ui", "--bin",
                "antinomie-monitor", "recorded_tracer_triage", "--", "--ignored", "--nocapture"]
        return argv, env
    return check.argv, {}


def input_result(ctx, name):
    """The result of check name: from this run, else from the last run in --out."""
    if name in ctx.get("results", {}):
        return ctx["results"][name]
    try:
        return json.loads((ctx["out"] / "results.json").read_text()).get(name)
    except (OSError, ValueError):
        return None


def missing(check, ctx):
    labels = {"old_base": "--old-base", "old": "--old-host", "base": "BASE",
              "tools": "--debugger-tools (a data folder with tools/gef and tools/pwndbg)"}
    keys = {"old": "old_ok", "tools": "debugger_ok"}
    for need in check.needs:
        if not ctx.get(keys.get(need, need)):
            return f"needs {labels[need]}"
    return None


def run_check(check, ctx, args, attempt):
    """One attempt: a result dict with status, seconds, log and the exit code."""
    out = ctx["out"]
    suffix = "" if attempt == 1 else f".try{attempt}"
    log = out / "logs" / f"{check.name}{suffix}.log"
    result = {"name": check.name, "group": check.group, "attempt": attempt, "log": str(log)}
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("")
    reason = missing(check, ctx)
    if reason:
        return {**result, "status": "SKIP", "seconds": 0.0, "detail": reason}
    problem = disk_problem(args)
    if problem:
        return {**result, "status": "ERROR", "seconds": 0.0, "detail": f"not started: {problem}"}
    runs = out / "runs" / check.name
    try:
        for stale in (runs, out / "runs" / f"{check.name}{suffix}"):
            safe_rmtree(stale, out)
        argv, extra = command_for(check, ctx, args)
        if check.vm:
            memwait(MIN_MEM_KIB, args.mem_wait_limit)
    except Failure as error:
        return {**result, "status": "ERROR", "seconds": 0.0, "detail": str(error)}
    env = private_env(out, check.name)
    env.update(extra)
    code, seconds = run_logged(argv, env, check.cwd, log, check.timeout)
    status = "TIMEOUT" if code is None else "PASS" if code == 0 else "FAIL"
    return {**result, "status": status, "seconds": round(seconds, 1), "exit": code}


def run_with_retries(check, ctx, args):
    attempts = []
    for attempt in range(1, args.retries + 2):
        result = run_check(check, ctx, args, attempt)
        attempts.append(result)
        print(f"  {check.name} attempt {attempt}: {result['status']} in {result['seconds']:.0f} s", flush=True)
        if result["status"] in ("PASS", "SKIP", "ERROR"):
            break
    final = dict(attempts[-1])
    final["attempts"] = attempts
    if final["status"] == "PASS" and len(attempts) > 1:
        final["status"] = "FLAKY"
    return final


# Report


def fmt_seconds(seconds):
    seconds = int(round(seconds))
    return f"{seconds // 60}m{seconds % 60:02d}s"


def report(results, order, header):
    rows = [header, ""]
    width = max([len(name) for name in order] + [5])
    rows.append(f"{'check':<{width}}  {'result':<8} {'time':>8}  log")
    total = 0.0
    for name in order:
        result = results.get(name)
        if result is None:
            rows.append(f"{name:<{width}}  {'-':<8} {'':>8}  not run")
            continue
        seconds = sum(a["seconds"] for a in result.get("attempts", [result]))
        total += seconds
        rows.append(f"{name:<{width}}  {result['status']:<8} {fmt_seconds(seconds):>8}  {result['log']}")
        for attempt in result.get("attempts", []):
            if len(result["attempts"]) > 1:
                rows.append(f"{'':<{width}}    attempt {attempt['attempt']}: {attempt['status']} "
                            f"{fmt_seconds(attempt['seconds'])}  {attempt['log']}")
        if result.get("detail"):
            rows.append(f"{'':<{width}}    {result['detail']}")
    counts = {s: sum(1 for r in results.values() if r["status"] == s) for s in ORDER}
    rows.append("")
    rows.append("total " + fmt_seconds(total) + "; " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    if counts["FLAKY"]:
        rows.append("FLAKY: passed only after a failed attempt, see the attempts above")
    return "\n".join(rows)


def exit_code(results, order):
    bad = [n for n in order if results.get(n) is None or results[n]["status"] not in ("PASS", "FLAKY")]
    return 1 if bad else 0


# Arguments


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("tier", choices=("quick", "full", "auto"))
    p.add_argument("base", help="BusyBox base bundle of the current guest series")
    p.add_argument("--old-base", help="an older BusyBox base: legacy checks and the new-host interop direction")
    p.add_argument("--old-host", metavar="REV|PATH",
                   help="old host for interop: a git rev built in a temporary worktree, or a built checkout "
                        "(default: the --against ref, else the nearest origin/release-*)")
    p.add_argument("--against", help="auto: ref to diff against (default: the nearest origin/release-*)")
    p.add_argument("--out", default="vm-regress-out", help="output folder (default: %(default)s)")
    p.add_argument("--only", action="append", default=[], metavar="CHECK", help="run only this check (repeatable)")
    p.add_argument("--skip", action="append", default=[], metavar="CHECK", help="skip this check (repeatable)")
    p.add_argument("--rerun-failed", action="store_true",
                   help="run the checks that did not pass (or never ran) in the last run in --out")
    p.add_argument("--retries", type=int, default=0, metavar="N",
                   help="rerun a failed check up to N more times; every attempt is reported and a pass "
                        "after a failure is shown as FLAKY (default: %(default)s)")
    p.add_argument("--debugger-tools", metavar="DIR",
                   help="a data folder holding tools/gef and tools/pwndbg for the debugger-live check")
    p.add_argument("--keep-data", action="store_true",
                   help="keep each check's VM disks and recordings (default: delete them once its result is recorded)")
    p.add_argument("--max-used-gb", type=int, default=380, metavar="GB",
                   help="do not start a check while the Linux disk uses more than this (default: %(default)s)")
    p.add_argument("--min-free", action="append", default=None, metavar="PATH:GB",
                   help="do not start a check while PATH has less than GB free (repeatable; "
                        "default on WSL: /mnt/e:5, the Windows drive behind the Linux disk)")
    p.add_argument("--no-build", action="store_true", help="use the examples already built")
    p.add_argument("--keep-old-host", action="store_true", help="keep the old host worktree in --out")
    p.add_argument("--mem-wait-limit", type=int, default=3 * 3600, metavar="S",
                   help="give up a boot after waiting this long for memory (default: %(default)s)")
    p.add_argument("--list", action="store_true", help="print the tier's checks and exit")
    return p


def parse(argv):
    args = parser().parse_args(argv)
    if args.retries < 0:
        raise SystemExit("--retries must not be negative")
    if args.min_free is None:
        args.min_free = default_min_free()
    for spec in args.min_free:
        path, _, limit = spec.rpartition(":")
        try:
            ok = bool(path) and float(limit) >= 0
        except ValueError:
            ok = False
        if not ok:
            raise SystemExit(f"--min-free {spec}: expected PATH:GB")
    if args.old_host and args.tier == "quick":
        raise SystemExit("--old-host is only for full or auto")
    return args


def protected_folders():
    """(folder, whole) pairs: whole means the folder and everything in it is off limits."""
    home = Path(os.path.expanduser("~"))
    xdg = {}
    for var, default in (("XDG_DATA_HOME", ".local/share"), ("XDG_CONFIG_HOME", ".config"),
                         ("XDG_CACHE_HOME", ".cache"), ("XDG_STATE_HOME", ".local/state")):
        xdg[var] = Path(os.environ.get(var) or home / default)
    keep = [Path("/"), home, home / ".local", *xdg.values()]
    inside = [home / "antinomie"] + [folder / "antinomie" for folder in xdg.values()]
    resolve = lambda path: Path(os.path.realpath(path))
    return [resolve(p) for p in keep], [resolve(p) for p in inside]


def forbid_user_folders(out):
    """The output folder must not be, hold or sit in the user's home, XDG folders or the app's data.

    out is compared by its real path, so a link to one of them is refused too.
    """
    out = Path(os.path.realpath(out))
    keep, inside = protected_folders()
    for folder in keep:
        if out == folder or out in folder.parents:
            raise Failure(f"--out {out} is or contains {folder}, which must never be cleaned")
    for private in inside:
        if out == private or private in out.parents or out in private.parents:
            raise Failure(f"--out {out} is inside {private}, which belongs to the app")


def main(argv=None):
    args = parse(argv if argv is not None else sys.argv[1:])
    out = Path(args.out).resolve()
    try:
        forbid_user_folders(out)
        tier = args.tier
        against = None
        if tier == "auto":
            against = args.against or default_against()
            paths, revision = changed_against(against)
            tier, reasons = choose_tier(paths, revision)
            print(f"auto: {tier} tier against {against}")
            for reason in reasons[:12]:
                print(f"  {reason}")
            if len(reasons) > 12:
                print(f"  ... and {len(reasons) - 12} more")
        base = Path(args.base).expanduser().resolve()
        old_base = Path(args.old_base).expanduser().resolve() if args.old_base else None
        for bundle in (base, old_base):
            if bundle and not (bundle / "bundle.json").is_file():
                raise Failure(f"{bundle} is not a base bundle (no bundle.json)")
        # Placeholders until the fixtures and the old host exist; plan() runs again then.
        ctx = {"out": out, "base": base, "old_base": old_base, "new": MONITOR / EXAMPLES,
               "fix": out / "fixtures", "old": out / "old-host-examples", "old_ok": False}
        checks = plan(tier, ctx)
        if args.list:
            for check in checks:
                print(f"{check.name:<20} {check.group:<8} timeout {check.timeout} s")
            return 0
        order = [check.name for check in checks]
        checks = select(checks, args.only, args.skip)
        results = {}
        results_file = out / "results.json"
        if args.rerun_failed:
            if not results_file.exists():
                raise Failure(f"--rerun-failed: no {results_file}")
            results = json.loads(results_file.read_text())
            checks = [c for c in checks if results.get(c.name, {}).get("status") not in ("PASS", "FLAKY")]
        out.mkdir(parents=True, exist_ok=True)
        selected = {check.name for check in checks}
        ctx["results"] = results
        cleanup = lambda: None
        try:
            if not selected:
                print("nothing to run")
            else:
                disk_guard(args)
                ctx["fix"] = build_fixtures(out)
                if not args.no_build:
                    disk_guard(args)
                    ctx["new"] = build_examples(ROOT, out, "build.log", app=bool(selected & {"tracer-qa", "debugger-live"}))
                if old_base and any("old" in c.needs for c in checks):
                    spec = args.old_host or against or default_against()
                    print(f"old host: {spec}", flush=True)
                    disk_guard(args)
                    ctx["old"], cleanup = old_host(spec, out)
                    ctx["old_ok"] = True
                if "debugger-live" in selected:
                    ctx["debugger_data"] = tools_dir(args, out)
                    ctx["debugger_ok"] = all((ctx["debugger_data"] / "tools" / t).is_dir() for t in ("gef", "pwndbg"))
                checks = [c for c in plan(tier, ctx) if c.name in selected]
                for check in checks:
                    print(f"{check.name} ...", flush=True)
                    results[check.name] = run_with_retries(check, ctx, args)
                    results_file.write_text(json.dumps(results, indent=1))
                    # tracer-qa reads tracer-record's recordings: that data goes after it.
                    if not args.keep_data and check.name != "tracer-record":
                        clean_check_data(out, check.name)
                        if check.name == "tracer-qa":
                            clean_check_data(out, "tracer-record")

        finally:
            if not args.keep_old_host:
                cleanup()
            if not args.keep_data:
                clean_check_data(out, "tracer-record")
        shown = [n for n in order if n in results or n in selected or not (args.only or args.skip)]
        text = report(results, shown, f"{tier} tier, base {base}")
        (out / "report.txt").write_text(text + "\n")
        print("\n" + text)
        return exit_code(results, shown)
    except Failure as error:
        print(f"vm-regress: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("vm-regress: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
