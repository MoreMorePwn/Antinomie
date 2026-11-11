#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Shared parts of the Auto mode VM tiers (design 7.2 T5 to T8):
tests/monitor/test-auto-smoke.py, test-auto-isolation.py, test-auto-faults.py
and test-auto-soak.py. Not a test by itself; tests/monitor/test-auto-harness.py
checks the parts that need no VM.

Every script works in a folder of its own (--work): a private HOME and XDG
folders, a data folder per lane set, a copy of the base (--base) so the
installed bundle is never the shared one, the CLI's output and the daemon's
log. The VM part runs inside --vm-slot (a command prefix that holds the
machine's VM slot, e.g. `flock heavy.lock vm-slot.sh`), and all VM data is
deleted at the end unless --keep. A process is only ever signalled by a PID
the harness recorded itself (the daemon it started) or that the service
recorded with the process's start time and command line (a lane's QEMU in
service/lanes/lane-N.json); never by name or pattern.

Timeouts are written at KVM speed and stretched by the time factor: 1 with
KVM, 4 under TCG (software emulation, e.g. a VPS without /dev/kvm), or
--time-factor / ANTINOMIE_TEST_TIME_FACTOR. The engine's own waits are
stretched by the CLI's --tcg-multiplier.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CLI = ROOT / "src/antinomie/monitor/target/release/antinomie-cli"
SAMPLE_BUILD = ROOT / "tests/monitor/build-behavior-samples.sh"
SLOT_ENV = "ANTINOMIE_VM_SLOT"
SLOT_HELD_ENV = "ANTINOMIE_VM_SLOT_HELD"
FACTOR_ENV = "ANTINOMIE_TEST_TIME_FACTOR"
TCG_FACTOR = 4.0
STAGES = ("prechecks", "provision", "upload", "launch", "run", "collect", "analyse", "report", "cleanup")
TERMINAL = ("succeeded", "partial", "failed", "cancelled", "rejected")
LABELS = ("malicious", "suspicious", "clean_observed", "inconclusive")
# A partial job whose only warnings are these is a host without every static
# tool (capa, FLOSS, ...) or a detection engine that had nothing to scan:
# the pipeline itself worked. --strict asks for `succeeded`.
HOST_TOOL_WARNINGS = ("static_check_incomplete", "detection_skipped")
GIB = 1 << 30
MIB = 1 << 20


class Failure(Exception):
    """A step that cannot go on; the script reports it and cleans up."""


class Abort(Failure):
    """Stopped from outside: the memory floor, a signal or the deadline."""


# ---------------------------------------------------------------- arguments


def ram_mib(text):
    value = int(text)
    if not 512 <= value <= 2048:
        raise argparse.ArgumentTypeError("guest RAM is 512 to 2048 MiB")
    return value


def common_parser(description, prog=None):
    p = argparse.ArgumentParser(prog=prog, description=description,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--work", type=Path, required=True,
                   help="folder of this run: private HOME/XDG, data folders, logs (created; reused by --resume)")
    p.add_argument("--base", type=Path, required=True,
                   help="BusyBox base bundle folder (bundle.json, kernel, disk); copied into --work first")
    p.add_argument("--cli", type=Path, default=DEFAULT_CLI,
                   help="the antinomie-cli binary [default: this repository's release build]")
    p.add_argument("--ram-mib", type=ram_mib, default=512, help="guest RAM, 512 to 2048 [512]")
    p.add_argument("--cpus", type=int, default=1, help="guest vCPUs [1]")
    p.add_argument("--disk-gib", type=int, default=4, help="lane VM disk [4]")
    p.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto",
                   help="auto: KVM when /dev/kvm opens, else TCG [auto]")
    p.add_argument("--time-factor", type=float, default=None,
                   help=f"stretch every wait of this script [${FACTOR_ENV}, else 1 with KVM, {TCG_FACTOR:g} under TCG]")
    p.add_argument("--tcg-multiplier", type=int, default=None,
                   help="passed to the CLI: how much longer the engine's guest waits are under TCG [CLI default]")
    p.add_argument("--vm-slot", default=os.environ.get(SLOT_ENV, ""),
                   help=f"command prefix that holds the VM slot for the VM part [${SLOT_ENV}], e.g. "
                        "'flock /path/heavy.lock /path/vm-slot.sh'")
    p.add_argument("--mem-gate-mb", type=int, default=5000,
                   help="wait for this much MemAvailable before each VM start [5000]")
    p.add_argument("--mem-floor-mb", type=int, default=2500,
                   help="stop the daemon (its recorded PID) when MemAvailable drops below this [2500]")
    p.add_argument("--min-free-gb", type=float, default=20.0,
                   help="refuse to start with less free disk under --work [20]")
    p.add_argument("--keep", action="store_true", help="keep the VM data (data folders, base copy) at the end")
    p.add_argument("--dry-run", action="store_true",
                   help="prepare the folder, build the programs, check the CLI and print the plan; start no VM")
    return p


def kvm_usable(path="/dev/kvm"):
    try:
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        return False
    os.close(fd)
    return True


def resolve_accel(choice, kvm):
    if choice == "auto":
        return "kvm" if kvm else "tcg"
    if choice == "kvm" and not kvm:
        raise Failure("--accel kvm, but /dev/kvm cannot be opened")
    return choice


def time_factor(given, accel, environ=None):
    environ = os.environ if environ is None else environ
    if given is not None:
        value = given
    elif environ.get(FACTOR_ENV):
        value = float(environ[FACTOR_ENV])
    else:
        value = TCG_FACTOR if accel == "tcg" else 1.0
    if value < 1:
        raise Failure("the time factor is at least 1")
    return value


def slot_argv(prefix, script, argv, python, environ=None):
    """The command that re-runs this script inside the VM slot, or None when
    there is no slot to take or it is already held (the marker variable)."""
    environ = os.environ if environ is None else environ
    if not prefix.strip() or environ.get(SLOT_HELD_ENV) == "1":
        return None
    return [*shlex.split(prefix), "env", f"{SLOT_HELD_ENV}=1", python, "-I", str(Path(script).resolve()), *argv]


def enter_vm_slot(prefix, script, argv):
    """Replace this process by itself under the slot prefix (it waits there
    while another VM user holds the slot)."""
    command = slot_argv(prefix, script, argv, sys.executable)
    if command:
        print(f"taking the VM slot (waits while another run holds it): {prefix}", flush=True)
        os.execvp(command[0], command)


# ---------------------------------------------------------------- machine


def mem_available_mb():
    with open("/proc/meminfo") as meminfo:
        for line in meminfo:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    return 0


def mem_gate(minimum_mb, limit_s, what, log=print):
    """Wait until MemAvailable is at least minimum_mb (other agents build and
    boot on the same machine); Failure after limit_s."""
    start = time.monotonic()
    said = 0.0
    while (available := mem_available_mb()) < minimum_mb:
        if time.monotonic() - start > limit_s:
            raise Failure(f"MemAvailable stayed under {minimum_mb} MB for {limit_s:.0f} s before {what}")
        if time.monotonic() - said > 60:
            log(f"     memory gate: MemAvailable {available} MB < {minimum_mb} MB before {what}, waiting")
            said = time.monotonic()
        time.sleep(20)
    return available


def disk_guard(path, min_free_gb):
    probe = Path(path)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free = shutil.disk_usage(probe).free / GIB
    if free < min_free_gb:
        raise Failure(f"{probe} has {free:.1f} GiB free, under --min-free-gb {min_free_gb:g}")
    return free


def stat_fields(pid):
    """(comm, fields after comm) of /proc/PID/stat, or None."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    head, _, tail = text.rpartition(")")
    return head.partition("(")[2], tail.split()


def start_ticks(pid):
    fields = stat_fields(pid)
    return int(fields[1][19]) if fields else None


def cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


def recorded_alive(record):
    """A QEMU record of a lane file ({pid, start_ticks, marker}) still names a
    live process: same PID, same start time, the marker in its command line."""
    if not record or not record.get("pid"):
        return False
    pid = int(record["pid"])
    fields = stat_fields(pid)
    if not fields or fields[1][0] == "Z":
        return False
    ticks = record.get("start_ticks")
    if ticks is not None and int(fields[1][19]) != int(ticks):
        return False
    return str(record.get("marker", "")) in cmdline(pid)


def kill_recorded(record, sig=signal.SIGKILL):
    """Signal a recorded process only after recorded_alive() says it is the one."""
    if recorded_alive(record):
        os.kill(int(record["pid"]), sig)
        return True
    return False


def safe_rmtree(path, root):
    """Remove path only when it is really below root (no link on the way)."""
    path, root = Path(path), Path(root)
    try:
        rel = Path(os.path.abspath(path)).relative_to(os.path.abspath(root))
    except ValueError:
        raise Failure(f"refusing to remove {path}: not below {root}") from None
    if rel == Path("."):
        raise Failure(f"refusing to remove {root} itself")
    if Path(os.path.realpath(path.parent)) != Path(os.path.realpath(root)) / rel.parent:
        raise Failure(f"refusing to remove {path}: a parent folder is a link leaving {root}")
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def tree_bytes(path, skip=()):
    total = 0
    for folder, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            try:
                total += os.lstat(os.path.join(folder, name)).st_size
            except OSError:
                pass
    return total


# ---------------------------------------------------------------- text helpers


def set_toml_key(text, section, key, value):
    """Set `key = value` (value already a TOML literal) in [section] of a
    policy or service.toml, replacing the line or adding it at the end of the
    section (the section is added when missing). Comments stay."""
    lines = text.splitlines()
    header = re.compile(r"^\s*\[([^\[\]]+)\]\s*(#.*)?$")
    assign = re.compile(rf"^\s*{re.escape(key)}\s*=")
    current, start, end = None, None, len(lines)
    for index, line in enumerate(lines):
        match = header.match(line)
        if match:
            if current == section:
                end = index
                break
            current = match[1].strip()
            if current == section:
                start = index
    if start is None:
        return text.rstrip("\n") + f"\n\n[{section}]\n{key} = {value}\n"
    for index in range(start + 1, end):
        if assign.match(lines[index]):
            comment = lines[index].partition("#")[2] if "#" in lines[index] else ""
            lines[index] = f"{key} = {value}" + (f"  # {comment.strip()}" if comment.strip() else "")
            return "\n".join(lines) + "\n"
    insert = end
    while insert > start + 1 and not lines[insert - 1].strip():
        insert -= 1
    lines.insert(insert, f"{key} = {value}")
    return "\n".join(lines) + "\n"


def toml_list(values):
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"


def service_toml(lanes=1, require_kvm=True, host_workers=None, min_free_disk_gib=None, retention=None):
    """The service.toml the tiers write: only what they change."""
    out = ["[daemon]", f"lanes = {int(lanes)}"]
    if host_workers is not None:
        out.append(f"host_workers = {int(host_workers)}")
    out += ["", "[resources]", f"require_kvm = {'true' if require_kvm else 'false'}"]
    if min_free_disk_gib is not None:
        out.append(f"min_free_disk_gib = {int(min_free_disk_gib)}")
    if retention:
        out += ["", "[retention]"] + [f"{k} = {json.dumps(v)}" for k, v in retention.items()]
    return "\n".join(out) + "\n"


def write_guest_script(path, body):
    """A benign shell program for the guest (BusyBox sh)."""
    path.write_text("#!/bin/sh\n" + body.strip() + "\n")
    path.chmod(0o755)
    return path


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------- job checks (pure)


def unwrap(document):
    """The `result` of the CLI's JSON envelope, or None for an error reply."""
    if not isinstance(document, dict):
        return None
    if document.get("ok") is False:
        return None
    return document.get("result", document)


def job_of(result):
    """A job object from `auto status JOB` or `auto submit` (`{job, ...}`)."""
    if isinstance(result, dict) and "id" not in result and isinstance(result.get("job"), dict):
        return result["job"]
    return result


def is_terminal(job):
    return isinstance(job, dict) and job.get("state") in TERMINAL


def warning_codes(job):
    return [w.get("code") for w in (job.get("warnings") or [])]


def outcome_ok(job, strict=False):
    """(ok, why): succeeded, or partial only for missing host tools."""
    state = job.get("state")
    if state == "succeeded":
        return True, "succeeded"
    if state == "partial" and not strict:
        others = sorted({c for c in warning_codes(job) if c not in HOST_TOOL_WARNINGS})
        if not others:
            return True, "partial (host tools only: " + ", ".join(sorted(set(warning_codes(job)))) + ")"
        return False, f"partial with {', '.join(others)}"
    failure = job.get("failure") or {}
    return False, f"{state} {failure.get('code', '')} {failure.get('message', '')}".strip()


def stage_durations(events):
    """{stage: duration_ms} of the last `finished` job.stage event of each stage."""
    out = {}
    for event in events:
        data = event.get("data") or {}
        if event.get("type") == "job.stage" and data.get("status") == "finished" and data.get("duration_ms") is not None:
            out[data.get("stage")] = int(data["duration_ms"])
    return out


def event_problems(events):
    """What is wrong with one job's stored events: numbering, first and last
    event, and the nine stages finishing in order."""
    problems = []
    seqs = [e.get("seq") for e in events]
    if seqs != list(range(1, len(seqs) + 1)):
        problems.append(f"seq is not 1..{len(seqs)} without a gap: {seqs[:12]}")
    types = [e.get("type") for e in events]
    if not types or types[0] != "job.created":
        problems.append(f"the first event is {types[:1]}, not job.created")
    if not types or types[-1] != "job.finished":
        problems.append(f"the last event is {types[-1:]}, not job.finished")
    finished = []
    for event in events:
        data = event.get("data") or {}
        if event.get("type") == "job.stage" and data.get("status") == "finished":
            if data.get("stage") not in finished:
                finished.append(data.get("stage"))
    missing = [s for s in STAGES if s not in finished]
    if missing:
        problems.append(f"no job.stage finished for {', '.join(missing)}")
    order = [s for s in finished if s in STAGES]
    if order != sorted(order, key=STAGES.index):
        problems.append(f"stages finished out of order: {order}")
    return problems


def host_work_problems(job):
    problems = []
    items = {item.get("name"): item for item in job.get("host_work") or []}
    for name in ("triage", "detection", "assess", "report"):
        if items.get(name, {}).get("state") != "done":
            problems.append(f"host item {name} is {items.get(name, {}).get('state', 'missing')}")
    for name, item in items.items():
        state = item.get("state")
        if state == "failed" and not (name.startswith("static:") and item.get("note")):
            problems.append(f"host item {name} failed: {item.get('note')}")
        if state in ("queued", "running"):
            problems.append(f"host item {name} is still {state}")
        expected, limit = item.get("expected_s"), item.get("limit_s")
        if expected is None or limit is None or limit < expected:
            problems.append(f"host item {name}: limit {limit} s below its expected {expected} s")
    return problems


def job_checks(job, *, lane=None, vm_name=None, base_identity=None, revert="snapshot_disk",
               exit_code=0, strict=False):
    """[(ok, message)] for a finished Auto job (design T5: the job object)."""
    out = []
    ok, why = outcome_ok(job, strict)
    out.append((ok, f"job {job.get('id')} ended {why}"))
    created, started, finished = (job.get(k) or 0 for k in ("created_ms", "started_ms", "finished_ms"))
    out.append((created <= started <= finished and finished > 0,
                f"times: created {created} <= started {started} <= finished {finished}"))
    out.append((job.get("stage") is None and job.get("waiting_for") is None, "no stage or wait left on the job"))
    if lane:
        out.append((job.get("lane") == lane, f"ran on {job.get('lane')} (expected {lane})"))
    vm = job.get("vm") or {}
    out.append((vm.get("revert") == revert, f"vm.revert is {vm.get('revert')} (expected {revert})"))
    if vm_name:
        out.append((vm.get("name") == vm_name, f"vm.name is {vm.get('name')} (expected {vm_name})"))
    if base_identity:
        out.append((vm.get("base_identity") == base_identity, "vm.base_identity is the installed base"))
    run = job.get("run") or {}
    out.append((bool(run.get("run_id")) and run.get("end_reason") == "exited" and run.get("exit") == exit_code,
                f"run {str(run.get('run_id'))[:12]} ended {run.get('end_reason')} with exit {run.get('exit')} "
                f"(expected exited, {exit_code})"))
    recording = job.get("recording") or {}
    out.append((recording.get("phase") == "complete" and recording.get("run_id") == run.get("run_id"),
                f"recording phase {recording.get('phase')}, same run as the job"))
    assessment = job.get("assessment") or {}
    out.append((assessment.get("label") in LABELS and bool(assessment.get("basis")),
                f"label {assessment.get('label')} with a basis sentence"))
    counts = assessment.get("counts") or {}
    out.append(((counts.get("processes") or 0) >= 1, f"the assessment counts {counts.get('processes')} process(es)"))
    kinds = {a.get("kind"): a for a in job.get("artifacts") or []}
    for kind in ("report.html", "report.json"):
        artifact = kinds.get(kind) or {}
        out.append(((artifact.get("size") or 0) > 0 and len(artifact.get("sha256") or "") == 64,
                    f"artifact {kind}: {artifact.get('size')} bytes"))
    problems = host_work_problems(job)
    out.append((not problems, "host work items done" + (": " + "; ".join(problems) if problems else "")))
    return out


def report_json_checks(report, job):
    """[(ok, message)] for the JSON report of a job (triage report schema 2)."""
    out = []
    schema = report.get("schema")
    out.append((schema == "antinomie-triage-report" and report.get("schema_version") == 2,
                f"report.json is {schema} version {report.get('schema_version')}"))
    run = report.get("run") or {}
    out.append((run.get("run_id") == (job.get("run") or {}).get("run_id")
                and run.get("vm_id") == (job.get("vm") or {}).get("id"),
                "report.json names the job's run and VM"))
    sample = report.get("sample") or {}
    out.append((sample.get("sha256") == (job.get("sample") or {}).get("sha256"), "report.json names the job's sample"))
    summary = report.get("summary") or {}
    want = (job.get("assessment") or {}).get("assessment")
    out.append((summary.get("assessment") == want, f"report.json assessment {summary.get('assessment')} = job's {want}"))
    out.append((isinstance(report.get("processes"), list) and len(report["processes"]) >= 1,
                f"report.json lists {len(report.get('processes') or [])} process(es)"))
    return out


# ---------------------------------------------------------------- the run folder


class Work:
    """One run's folder: home/, out/ (logs and evidence, kept), data*/ and the
    base copy (VM data, deleted at the end)."""

    def __init__(self, root, name="data"):
        self.root = Path(root).resolve()
        self.home = self.root / "home"
        self.out = self.root / "out"
        self.data = self.root / name
        self.samples = self.root / "programs"

    def prepare(self):
        for folder in (self.root, self.home, self.out, self.samples):
            folder.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        return self

    def env(self):
        env = dict(os.environ)
        for var, sub in (("HOME", ""), ("XDG_DATA_HOME", ".local/share"), ("XDG_CONFIG_HOME", ".config"),
                         ("XDG_CACHE_HOME", ".cache"), ("XDG_STATE_HOME", ".local/state")):
            folder = self.home / sub if sub else self.home
            folder.mkdir(parents=True, exist_ok=True)
            env[var] = str(folder)
        for var in ("WAYLAND_DISPLAY", "DISPLAY", SLOT_HELD_ENV):
            env.pop(var, None)
        return env

    def copy_base(self, base):
        """A private copy of the base bundle (the shared folder stays untouched)."""
        base = Path(base).resolve()
        if not (base / "bundle.json").is_file():
            raise Failure(f"{base} is not a base bundle folder (no bundle.json)")
        target = self.root / "base-copy" / base.name
        if not (target / "bundle.json").is_file():
            if target.exists():
                safe_rmtree(target, self.root)
            shutil.copytree(base, target, symlinks=False)
        return target

    def lane_dir(self, lane):
        return self.data if int(lane) == 1 else self.data / "lanes" / str(int(lane))

    def lane_file(self, lane):
        return self.data / "service" / "lanes" / f"lane-{int(lane)}.json"

    def read_lane_file(self, lane):
        try:
            return json.loads(self.lane_file(lane).read_text())
        except (OSError, ValueError):
            return None

    def write_lane_file(self, lane, value):
        """Rewrite a lane file atomically (only with the daemon stopped)."""
        path = self.lane_file(lane)
        temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        temp.write_text(json.dumps(value, indent=2) + "\n")
        os.chmod(temp, 0o600)
        os.replace(temp, path)

    def lane_files(self):
        folder = self.data / "service" / "lanes"
        return sorted(folder.glob("lane-*.json")) if folder.is_dir() else []

    def policy(self, name):
        return self.data / "policies" / f"{name}.toml"


# ---------------------------------------------------------------- the CLI


class Cli:
    """antinomie-cli with the run's data folder and private environment;
    every call is logged to out/cli.log."""

    def __init__(self, binary, work, accel, tcg_multiplier=None, data=None):
        self.binary, self.work, self.accel = Path(binary), work, accel
        self.tcg_multiplier = tcg_multiplier
        self.data = Path(data) if data else work.data
        self.env = work.env()
        self.log = work.out / "cli.log"

    def with_data(self, data):
        return Cli(self.binary, self.work, self.accel, self.tcg_multiplier, data)

    def argv(self, args, engine=False, daemon=False):
        head = [str(self.binary), "--data-dir", str(self.data), "-o", "json"]
        if engine and self.accel == "tcg":
            head.append("--tcg")
            if self.tcg_multiplier:
                head += ["--tcg-multiplier", str(self.tcg_multiplier)]
        if daemon:
            head.append("--daemon")
        return head + [str(a) for a in args]

    def run(self, *args, engine=False, daemon=False, timeout=600, stdin=None):
        """(exit code, parsed stdout or None, stderr text)."""
        argv = self.argv(args, engine, daemon)
        started = time.monotonic()
        try:
            done = subprocess.run(argv, env=self.env, cwd=self.work.root, capture_output=True, text=True,
                                  timeout=timeout, input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)
            code, out, err = done.returncode, done.stdout, done.stderr
        except subprocess.TimeoutExpired as expired:
            code = None
            out = expired.stdout.decode(errors="replace") if isinstance(expired.stdout, bytes) else (expired.stdout or "")
            err = expired.stderr.decode(errors="replace") if isinstance(expired.stderr, bytes) else (expired.stderr or "")
        with open(self.log, "a") as log:
            log.write(f"$ {shlex.join(argv[3:])}\n# exit {code} in {time.monotonic() - started:.1f} s\n")
            if err.strip():
                log.write("".join(f"! {line}\n" for line in err.strip().splitlines()[-40:]))
            log.write(out[-4000:] + ("\n" if out and not out.endswith("\n") else ""))
        try:
            parsed = json.loads(out) if out.strip() else None
        except ValueError:
            parsed = None
        return code, parsed, err

    def ok(self, *args, **kwargs):
        """The result of a call that must work; Failure otherwise."""
        code, parsed, err = self.run(*args, **kwargs)
        result = unwrap(parsed)
        if code != 0 or result is None:
            tail = (err.strip().splitlines() or [""])[-1]
            error = (parsed or {}).get("error") if isinstance(parsed, dict) else None
            raise Failure(f"`{' '.join(map(str, args[:3]))}` exit {code}: {error or tail}")
        return result

    def version(self):
        done = subprocess.run([str(self.binary), "--version"], env=self.env, capture_output=True, text=True, timeout=60)
        return done.stdout.strip() or done.stderr.strip()

    def help_text(self, *args):
        done = subprocess.run([str(self.binary), *args, "--help"], env=self.env, capture_output=True, text=True,
                              timeout=60)
        return done.stdout + done.stderr


def missing_flags(help_text, flags):
    """The flags a step uses that the CLI's --help does not mention."""
    return [flag for flag in flags if not re.search(rf"(^|[\s,\[]){re.escape(flag)}([\s=,\]]|$)", help_text, re.M)]


# The commands and flags the tiers call: a dry run checks them against --help.
CLI_SURFACE = {
    ("base", "install"): (),
    ("auto", "init"): ("--lane", "--ram-mib", "--cpus", "--disk-gib", "--name", "--snapshot"),
    ("auto", "daemon"): (),
    ("auto", "submit"): ("--policy", "--timeout-run", "--args", "--as", "--name"),
    ("auto", "status"): (),
    ("auto", "events"): ("--all",),
    ("auto", "fetch"): ("--out",),
    ("auto", "cancel"): (),
    ("auto", "lane", "list"): (),
    ("auto", "lane", "reset"): ("--yes", "--lane"),
    ("auto", "gc"): ("--dry-run",),
    ("config", "validate"): ("--policy",),
    ("snapshot", "create"): ("--mode",),
    ("snapshot", "restore"): ("--yes", "--cold-boot"),
    ("run", "list"): ("--job",),
    ("sample", "show"): ("--events",),
    ("custody", "verify"): (),
    (): ("--data-dir", "--tcg", "--tcg-multiplier", "--daemon", "--format"),
}


def check_cli_surface(cli):
    """[(ok, message)]: the binary runs and has every command and flag used."""
    out = []
    if not cli.binary.is_file() or not os.access(cli.binary, os.X_OK):
        return [(False, f"no CLI at {cli.binary}: build it (see the task record's phase-2 steps) or pass --cli")]
    out.append((True, f"CLI {cli.binary}: {cli.version()}"))
    for command, flags in CLI_SURFACE.items():
        text = cli.help_text(*command)
        missing = missing_flags(text, flags)
        known = "Usage:" in text or "usage:" in text
        out.append((known and not missing,
                    f"`{' '.join(command) or 'antinomie-cli'} --help`" + (f" lacks {', '.join(missing)}" if missing else "")
                    + ("" if known else " did not print a usage")))
    return out


# ---------------------------------------------------------------- the daemon


class Daemon:
    """`auto daemon` started by the harness: its PID is recorded at start and
    is the only PID the harness signals for it."""

    def __init__(self, cli, factor, log_name="daemon"):
        self.cli, self.factor = cli, factor
        self.log_path = cli.work.out / f"{log_name}.log"
        self.process = None
        self.starts = 0

    @property
    def pid(self):
        return self.process.pid if self.process else None

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def start(self, tag="", gate_mb=5000):
        mem_gate(gate_mb, 3600 * self.factor, f"the daemon start {tag}".strip())
        self.starts += 1
        log = open(self.log_path, "a")
        log.write(f"\n==== start {self.starts} {tag} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        log.flush()
        self.process = subprocess.Popen(self.cli.argv(["auto", "daemon"], engine=True), env=self.cli.env,
                                        cwd=self.cli.work.root, stdout=log, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, start_new_session=True)
        log.close()
        socket = self.cli.data / "run" / "antinomie.sock"
        deadline = time.monotonic() + 120 * self.factor
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise Failure(f"the daemon exited {self.process.returncode} at start; see {self.log_path}")
            if socket.exists():
                code, parsed, _ = self.cli.run("auto", "status", daemon=True, timeout=60)
                if code == 0 and unwrap(parsed) is not None:
                    return unwrap(parsed)
            time.sleep(1)
        raise Failure(f"the daemon did not answer within {120 * self.factor:.0f} s; see {self.log_path}")

    def signal(self, sig):
        if self.alive():
            os.kill(self.process.pid, sig)

    def stop(self, grace=None):
        """SIGTERM, then SIGKILL after grace (the unit's 360 s, stretched)."""
        if not self.process:
            return None
        grace = 360 * self.factor if grace is None else grace
        self.signal(signal.SIGTERM)
        try:
            return self.process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.signal(signal.SIGKILL)
            return self.process.wait(timeout=60)

    def kill(self):
        """SIGKILL now (fault injection): the recorded PID only."""
        self.signal(signal.SIGKILL)
        return self.process.wait(timeout=60) if self.process else None

    def owner_pid(self):
        try:
            return json.loads((self.cli.data / "run" / "owner.json").read_text()).get("pid")
        except (OSError, ValueError):
            return None


class MemWatch(threading.Thread):
    """Samples MemAvailable every 2 s into out/mem.log; below the floor it
    stops the daemon (SIGTERM to its recorded PID) and marks the run."""

    def __init__(self, work, floor_mb, daemon=None, period=2.0):
        super().__init__(daemon=True)
        self.work, self.floor, self.target, self.period = work, floor_mb, daemon, period
        self.tripped = None
        self.minimum = None
        self.halt = threading.Event()

    def run(self):
        with open(self.work.out / "mem.log", "a") as log:
            while not self.halt.wait(self.period):
                available = mem_available_mb()
                self.minimum = available if self.minimum is None else min(self.minimum, available)
                rss = 0
                if self.target and self.target.alive():
                    rss = process_tree_rss_kib(self.target.pid)
                log.write(f"{time.strftime('%H:%M:%S')} mem={available} tree_rss_kib={rss}\n")
                log.flush()
                if available < self.floor and self.tripped is None:
                    self.tripped = f"MemAvailable {available} MB fell below the floor of {self.floor} MB"
                    log.write(f"STOP: {self.tripped}\n")
                    if self.target:
                        self.target.signal(signal.SIGTERM)

    def check(self):
        if self.tripped:
            raise Abort(self.tripped)

    def stop(self):
        self.halt.set()


def children(pid):
    out = []
    for task in Path(f"/proc/{pid}/task").glob("*"):
        try:
            out += [int(p) for p in (task / "children").read_text().split()]
        except OSError:
            pass
    return out


def process_tree_rss_kib(pid):
    total, todo, seen = 0, [pid], set()
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        total += status_kib(current, "VmRSS")
        todo += children(current)
    return total


def status_kib(pid, field):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(field + ":"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def open_fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


# ---------------------------------------------------------------- reporting


class Checks:
    def __init__(self, work, title):
        self.items, self.title = [], title
        self.log = work.out / "checks.log"
        self.say(f"== {title}")

    def say(self, text):
        print(text, flush=True)
        with open(self.log, "a") as log:
            log.write(text + "\n")

    def check(self, ok, message):
        self.items.append((bool(ok), message))
        self.say(("ok   " if ok else "FAIL ") + message)
        return bool(ok)

    def all(self, pairs, prefix=""):
        return all([self.check(ok, prefix + message) for ok, message in pairs])

    def note(self, message):
        self.say("     " + message)

    def failures(self):
        return [message for ok, message in self.items if not ok]

    def summary(self):
        failed = self.failures()
        self.say(f"== {self.title}: {len(self.items) - len(failed)} of {len(self.items)} checks hold"
                 + (f"; failed: {len(failed)}" if failed else ""))
        return 1 if failed else 0


# ---------------------------------------------------------------- steps


def install_base(cli, base_copy):
    result = cli.ok("base", "install", base_copy, engine=True, timeout=1800)
    installed = result.get("installed") or []
    if not installed:
        raise Failure("base install listed no installed base")
    return installed[0]


def init_lane(cli, args, lane=1, gate=True, name=None, factor=1.0):
    if gate:
        mem_gate(args.mem_gate_mb, 3600 * factor, f"auto init --lane {lane}")
    extra = ["--name", name] if name else []
    result = cli.ok("auto", "init", "--lane", lane, "--ram-mib", args.ram_mib, "--cpus", args.cpus,
                    "--disk-gib", args.disk_gib, *extra, engine=True, timeout=int(1800 * factor))
    return result.get("lane") or result


def edit_policy(work, name, changes, source="default"):
    """Write policies/<name>.toml: the default policy auto init wrote, with
    changes {(section, key): toml literal}."""
    text = work.policy(source).read_text()
    for (section, key), value in changes.items():
        text = set_toml_key(text, section, key, value)
    path = work.policy(name)
    path.write_text(text)
    return path


def submit(cli, program, *, policy=None, timeout_run=None, run_as=None, name=None, args=()):
    argv = ["auto", "submit", program]
    if policy:
        argv += ["--policy", policy]
    if timeout_run:
        argv += ["--timeout-run", timeout_run]
    if run_as:
        argv += ["--as", run_as]
    if name:
        argv += ["--name", name]
    if args:
        argv += ["--args", *args]
    job = job_of(cli.ok(*argv, daemon=True, timeout=600))
    if not job or not job.get("id"):
        raise Failure(f"auto submit {Path(program).name} returned no job")
    return job


def job_status(cli, job_id):
    code, parsed, _ = cli.run("auto", "status", job_id, daemon=True, timeout=120)
    return job_of(unwrap(parsed)) if code == 0 else None


def wait_job(cli, job_id, timeout, until=is_terminal, poll=3.0, watch=None, daemon=None):
    """Poll `auto status JOB` until `until(job)`; the job, or Failure."""
    deadline = time.monotonic() + timeout
    job = None
    while time.monotonic() < deadline:
        if watch:
            watch.check()
        if daemon is not None and not daemon.alive():
            raise Failure(f"the daemon exited ({daemon.process.returncode}) while waiting for {job_id}")
        job = job_status(cli, job_id) or job
        if job and until(job):
            return job
        time.sleep(poll)
    where = f"state {job.get('state')} stage {job.get('stage')} waiting_for {job.get('waiting_for')}" if job else "unknown"
    raise Failure(f"job {job_id} did not reach the condition within {timeout:.0f} s ({where})")


def in_stage(stage):
    return lambda job: is_terminal(job) or job.get("stage") == stage


def events_of(cli, job_id, **kwargs):
    result = cli.ok("auto", "events", job_id, timeout=120, **kwargs)
    return result.get("items", []) if isinstance(result, dict) else []


def fetch_artifact(cli, job_id, kind, folder):
    folder.mkdir(parents=True, exist_ok=True)
    result = cli.ok("auto", "fetch", job_id, kind, "--out", folder, daemon=True, timeout=300)
    written = Path(result.get("written") or "")
    if not written.is_file():
        candidates = sorted(folder.glob(f"*.{kind}")) or sorted(folder.iterdir())
        written = candidates[-1] if candidates else written
    return written


def lane_list(cli, daemon=True):
    result = cli.ok("auto", "lane", "list", daemon=daemon, timeout=120)
    return {item.get("lane"): item for item in result.get("items", [])}


def build_sample(work, scenario):
    """demo-<scenario> from tests/monitor/behavior-samples (benign stand-ins),
    built once per run folder."""
    target = work.samples / f"demo-{scenario}"
    if not target.is_file():
        log = work.out / "build-samples.log"
        with open(log, "a") as out:
            done = subprocess.run(["bash", str(SAMPLE_BUILD), str(work.samples)], cwd=ROOT, stdout=out,
                                  stderr=subprocess.STDOUT, timeout=1800, env=work.env())
        if done.returncode or not target.is_file():
            raise Failure(f"build-behavior-samples.sh exit {done.returncode} or no demo-{scenario}; see {log}")
    return target


# The offline arguments: every connection goes to a closed local port and the
# job's route drops what leaves the guest anyway.
SAMPLE_ARGS = ("--host", "127.0.0.1", "--port", "9", "--rounds", "1", "--delay", "0", "--gap", "0")


def cleanup(work, daemons=(), keep=False, data_folders=None, say=print, data_root=None):
    """End what this run started and delete its VM data.

    The daemons get SIGTERM, then SIGKILL (their recorded PIDs). A lane's
    QEMU still running is killed only through its lane-file record (PID,
    start time and command line checked). A QEMU process that names this
    folder but was not recorded is reported, never signalled."""
    for daemon in daemons:
        if daemon and daemon.alive():
            code = daemon.stop()
            say(f"     cleanup: daemon {daemon.pid} stopped with {code}")
    folders = data_folders if data_folders is not None else [work.data]
    for data in folders:
        lanes = Path(data) / "service" / "lanes"
        for path in sorted(lanes.glob("lane-*.json")) if lanes.is_dir() else []:
            try:
                record = json.loads(path.read_text()).get("qemu")
            except (OSError, ValueError):
                record = None
            if kill_recorded(record):
                say(f"     cleanup: killed the recorded QEMU {record['pid']} of {path.name}")
    time.sleep(1)
    stray = [pid for pid in (int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit())
             if (stat_fields(pid) or ("",))[0].startswith("qemu-system") and str(work.root) in cmdline(pid)]
    for pid in stray:
        say(f"     cleanup: QEMU {pid} names {work.root} but was not recorded; not signalled, check it by hand")
    if keep:
        say(f"     cleanup: --keep, the VM data stays in {work.root}")
        return stray
    for data in folders:
        if Path(data).exists():
            safe_rmtree(data, data_root or work.root)
    for name in ("base-copy",):
        if (work.root / name).exists():
            safe_rmtree(work.root / name, work.root)
    say(f"     cleanup: VM data deleted; logs stay in {work.out}")
    return stray


def preamble(args, script_path, argv, title):
    """Parse-time work common to every tier: accel, factor, run folder,
    the dry-run's CLI check, then the VM slot. Returns (work, cli, factor)."""
    accel = resolve_accel(args.accel, kvm_usable())
    factor = time_factor(args.time_factor, accel)
    work = Work(args.work).prepare()
    cli = Cli(args.cli, work, accel, args.tcg_multiplier)
    free = disk_guard(work.root, args.min_free_gb)
    print(f"{title}: accel {accel}{' (TCG on this host: no usable /dev/kvm)' if accel == 'tcg' else ''}, "
          f"time factor {factor:g}, guest {args.ram_mib} MiB x {args.cpus} vCPU, {free:.0f} GiB free, "
          f"MemAvailable {mem_available_mb()} MB, work {work.root}", flush=True)
    return work, cli, accel, factor


def dry_run(work, cli, checks, plan):
    """Print the plan and check the CLI; nothing starts a VM."""
    checks.all(check_cli_surface(cli))
    checks.note("plan (no VM was started):")
    for step in plan:
        checks.note(f"  {step}")
    return checks.summary()
