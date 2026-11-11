#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Nightly end-to-end check on a real VM: the newest BusyBox base for this
app version boots, a heavy launched program and the same load under Capture
All are recorded in never-drop mode without loss or parser errors (the guest
runs slower instead) and Capture All names the processes; with Capture All
allowed to drop when the host falls behind, it loses telemetry only while it
sheds; and a network capture records packets. With the CLI given, one Auto
job also runs end to end: `auto init` makes a lane on the base and a benign
shell script goes through every stage in the command itself (no daemon) to a
report. Needs KVM, QEMU, bubblewrap (for the Auto job) and the release
guest-run example (and antinomie-cli).

    nightly-vm.py GUEST_RUN WORK_DIR [CLI]
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

# The Auto mode tiers' checks of a job (tests/monitor/auto_vm.py).
_spec = importlib.util.spec_from_file_location(
    "auto_vm", Path(__file__).resolve().parents[2] / "tests/monitor/auto_vm.py")
auto_vm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auto_vm)

BUCKET = "https://huggingface.co/buckets/MoreMorePwn/antinomie-bases/resolve"
# Heavy enough to overflow the guest buffers, small enough for a CI runner.
# The programs are run by path: the bases' static BusyBox shell runs a bare
# `ls` as an applet in a forked child without an execve, so nothing in the
# guest's telemetry would name it ls (it is the shell, forked).
WORKLOAD = ("/bin/ls -lR / >/dev/null 2>&1; /bin/cat /proc/kallsyms >/dev/null; "
            "/bin/find / -xdev >/dev/null 2>&1; echo LOAD DONE")


def app_version():
    cargo = Path(__file__).resolve().parents[2] / "src/antinomie/monitor/Cargo.toml"
    for line in cargo.read_text().splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise SystemExit("no workspace version in Cargo.toml")


def release(version):
    return tuple(int(part) for part in version.split("."))


def download_base(version, target):
    with urllib.request.urlopen(f"{BUCKET}/index.json", timeout=60) as reply:
        catalog = json.load(reply)
    # The newest base this version runs: a patch release keeps its minor's bases.
    bases = [base for base in catalog["bases"]
             if base["kind"] == "busybox" and base.get("min_app_version")
             and release(base["min_app_version"]) <= release(version)]
    if not bases:
        raise SystemExit(f"no BusyBox base for Antinomie {version} in the catalog")
    base = max(bases, key=lambda base: (release(base["min_app_version"]), base["created"]))
    directory = target / base["identity"]
    directory.mkdir(parents=True, exist_ok=True)
    for file in base["files"]:
        path = directory / file["name"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != file["sha256"]:
            url = f"{BUCKET}/bases/{base['identity']}/{file['name']}"
            with urllib.request.urlopen(url, timeout=300) as reply:
                path.write_bytes(reply.read())
        if hashlib.sha256(path.read_bytes()).hexdigest() != file["sha256"]:
            raise SystemExit(f"{file['name']} does not match the catalog SHA-256")
    print(f"base {base['identity'][:16]} ({base['label']}, "
          f"Antinomie {base['min_app_version']})", flush=True)
    return directory


def run(guest_run, work, name, plan):
    path = work / f"{name}.json"
    path.write_text(json.dumps(plan))
    print(f"== {name}", flush=True)
    done = subprocess.run([guest_run, str(path)], capture_output=True, text=True, timeout=1800)
    (work / f"{name}.stderr").write_text(done.stderr)
    (work / f"{name}.result.json").write_text(done.stdout)
    if done.returncode:
        print(done.stderr[-3000:])
        raise SystemExit(f"{name}: guest-run failed")
    return json.loads(done.stdout)


def check(condition, message, failures):
    print(("ok   " if condition else "FAIL ") + message, flush=True)
    if not condition:
        failures.append(message)


AUTO_PROGRAM = """#!/bin/sh
# Nightly Auto job (benign).
echo "nightly auto $(uname -r)"
ls -l / > /dev/null
sleep 2
"""


def auto_job(cli, base, work, failures):
    """One Auto job: a lane on the base, a shell script submitted and run in
    the command (no daemon), the job's outcome, run and report files."""
    data, home = work / "data-auto", work / "home-auto"
    home.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "share"), XDG_CONFIG_HOME=str(home / "config"),
               XDG_CACHE_HOME=str(home / "cache"))
    log = work / "auto.stderr"

    def call(*args, timeout=900):
        done = subprocess.run([cli, "--data-dir", str(data), "-o", "json", *map(str, args)], env=env,
                              capture_output=True, text=True, timeout=timeout)
        with open(log, "a") as file:
            file.write(f"$ {' '.join(map(str, args))}\n{done.stderr}\nexit {done.returncode}\n")
        try:
            return done.returncode, auto_vm.unwrap(json.loads(done.stdout))
        except ValueError:
            return done.returncode, None

    print("== auto", flush=True)
    code, _ = call("base", "install", base)
    check(code == 0, f"auto: base install exit {code}", failures)
    code, lane = call("auto", "init", "--ram-mib", 1024, "--cpus", 2, "--disk-gib", 2)
    check(code == 0 and bool(lane), f"auto: auto init exit {code}", failures)
    if code != 0:
        return
    policy = data / "policies" / "default.toml"
    policy.write_text(auto_vm.set_toml_key(policy.read_text(), "sample", "accept_types", '["elf", "sh"]'))
    (data / "service.toml").write_text(auto_vm.service_toml(min_free_disk_gib=2))
    program = work / "auto-job.sh"
    program.write_text(AUTO_PROGRAM)
    program.chmod(0o755)
    code, result = call("auto", "submit", program, "--timeout-run", 60, "--wait", timeout=1800)
    job = auto_vm.job_of(result) or {}
    if job.get("id"):
        code_status, status = call("auto", "status", job["id"], timeout=120)
        job = auto_vm.job_of(status) if code_status == 0 and status else job
    ok, why = auto_vm.outcome_ok(job)
    check(code in (0, 11) and ok, f"auto: the job ended {why} (exit {code})", failures)
    run = job.get("run") or {}
    check(run.get("exit") == 0 and (job.get("recording") or {}).get("phase") == "complete",
          f"auto: the program exited {run.get('exit')}, recording {(job.get('recording') or {}).get('phase')}",
          failures)
    kinds = {artifact.get("kind") for artifact in job.get("artifacts") or []}
    check({"report.html", "report.json"} <= kinds, f"auto: report files {sorted(kinds)}", failures)


def main():
    guest_run, work = sys.argv[1], Path(sys.argv[2]).resolve()
    cli = sys.argv[3] if len(sys.argv) > 3 else None
    work.mkdir(parents=True, exist_ok=True)
    version = app_version()
    base = download_base(version, work / "bases")
    failures = []
    vm = {"cpus": 2, "ram_mib": 1024, "disk_gib": 2}
    heavy = [{"path": "/bin/sh", "args": ["-c", WORKLOAD], "uid": 0, "gid": 0,
              "done": "LOAD DONE", "timeout": 900}]
    # Never drop (the default transport) holds for a launched program, and
    # under Capture All too: the guest waits for the host instead.
    for name, capture_all in (("never-drop", False), ("capture-all", True)):
        result = run(guest_run, work, name, {
            "data_dir": str(work / f"data-{name}"), "headless": True, "import": str(base),
            "vm": vm | {"name": name}, "boot_timeout": 240, "capture_all": capture_all,
            "runs": heavy})
        health = result["health"]
        print(f"     the workload took {result['runs'][0]['seconds']:.1f} s", flush=True)
        check(health["attempted"] > 100_000, f"{name}: heavy workload sent {health['attempted']} packets", failures)
        check(health["dropped"] == 0, f"{name}: never-drop lost {health['dropped']} packets", failures)
        check(health.get("shed_count", 0) == 0, f"{name}: shed {health.get('shed_count')} times, not allowed to", failures)
        check(health["parser_errors"] == 0, f"{name}: {health['parser_errors']} parser errors", failures)
        check(health.get("persistence_error") is None, f"{name}: saving error: {health.get('persistence_error')}", failures)
        check(result["runs"][0]["marker_seen"], f"{name}: launched program finished with its output", failures)
    processes = [json.loads(path.read_text())
                 for path in (work / "data-capture-all").rglob("processes.json")]
    named = [p for tree in processes for p in tree if p.get("name")]
    check(any(p["name"] == "sh" and p.get("exe") == "/bin/sh" for p in named)
          and any(p["name"] == "ls" and p.get("exe") == "/bin/ls" for p in named),
          f"capture named {len(named)} processes, including sh and ls", failures)
    # Allowed to drop under Capture All, it does so only while it sheds load.
    shed_run = run(guest_run, work, "capture-all-shed", {
        "data_dir": str(work / "data-capture-all-shed"), "headless": True, "import": str(base),
        "vm": vm | {"name": "Shed", "transport": {"capture_all_shed": True}},
        "boot_timeout": 240, "capture_all": True, "runs": heavy})
    health = shed_run["health"]
    shed = health.get("shed_count", 0)
    print(f"     the workload took {shed_run['runs'][0]['seconds']:.1f} s", flush=True)
    check(health["dropped"] == 0 or shed > 0,
          f"capture-all-shed: lost {health['dropped']} of {health['attempted']} packets, only while "
          f"shedding (spells: {shed}, {health.get('shed_ns', 0) / 1e9:.1f} s)", failures)
    check(health["parser_errors"] == 0, f"capture-all-shed: {health['parser_errors']} parser errors", failures)
    check(shed_run["runs"][0]["marker_seen"], "capture-all-shed: launched program finished with its output", failures)
    network = run(guest_run, work, "network", {
        "data_dir": str(work / "data-network"), "headless": True, "import": str(base),
        "vm": vm | {"name": "Network", "nat": True}, "boot_timeout": 240,
        "network_capture": True,
        "runs": [{"path": "/bin/sh", "args": ["-c", "nslookup example.com 10.0.2.3; "
                  "ping -c 3 10.0.2.2; echo LOAD DONE"], "uid": 0, "gid": 0,
                  "done": "LOAD DONE", "timeout": 120}]})
    captures = network.get("network_captures") or []
    packets = max((c.get("packets") or 0 for c in captures), default=0)
    sizes = max((c.get("bytes") or 0 for c in captures), default=0)
    check(bool(captures) and sizes > 24, f"network capture recorded {sizes} bytes ({packets} packets counted)", failures)
    if cli:
        auto_job(cli, base, work, failures)
    if failures:
        raise SystemExit(f"{len(failures)} check(s) failed")
    print("all checks passed")


if __name__ == "__main__":
    main()
