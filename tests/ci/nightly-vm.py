#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Nightly end-to-end check on a real VM: the newest BusyBox base for this
app version boots, a heavy launched program and the same load under Capture
All are recorded in never-drop mode without loss or parser errors (the guest
runs slower instead) and Capture All names the processes; with Capture All
allowed to drop when the host falls behind, it loses telemetry only while it
sheds; and a network capture records packets. Needs KVM, QEMU and the release
guest-run example.

    nightly-vm.py GUEST_RUN WORK_DIR
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

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


def main():
    guest_run, work = sys.argv[1], Path(sys.argv[2]).resolve()
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
    if failures:
        raise SystemExit(f"{len(failures)} check(s) failed")
    print("all checks passed")


if __name__ == "__main__":
    main()
