#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""ANT-T0612: where a run's `collect` spends its time after the trace cap.

One Auto job on a real VM: the benign high-rate fixture
(tests/monitor/trace-cap-fixture.c, getpid() and non-blocking connect() to
never-routed addresses) runs under `auto daemon` with a small
`[resources] trace_cap_mib` (--cap-mib, 256 by default) until the cap stops
it. The script prints and saves (out/trace-cap.json):

* the stage times, and how long the lane held the VM (`provision` to the end
  of `collect`);
* the `run.collect` parts (evidence, telemetry, stop, saving, disk layer, and
  the parts after the lane let the VM go) and the daemon's `collect took`
  line;
* the host work items and their times;
* the earlier bytes the recording kept (file-before/index.json): the fixture
  appends a line to /etc/hostname, so that file must be there.

    test-auto-trace-cap.py --work DIR --base BASE [--cap-mib 256] [--vm-slot PREFIX]

Checks: the job ends `partial` with `trace_cap_reached`, every collect part
is timed, /etc/hostname's earlier bytes are kept, and the lane is free and
clean afterwards. Exit 0 when every check holds, 1 otherwise.
"""
import importlib.util
from pathlib import Path
import json
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("auto_vm", Path(__file__).resolve().with_name("auto_vm.py"))
av = importlib.util.module_from_spec(spec)
sys.modules["auto_vm"] = av
spec.loader.exec_module(av)

FIXTURE = Path(__file__).resolve().with_name("trace-cap-fixture.c")
JOB_TIMEOUT_S = 3600
CHANGED_FILE = "/etc/hostname"


def parser():
    p = av.common_parser(__doc__, prog="test-auto-trace-cap.py")
    p.add_argument("--cap-mib", type=int, default=256, help="[resources] trace_cap_mib [256]")
    p.add_argument("--run-s", type=int, default=300, help="the run limit; the cap should stop it first [300]")
    p.add_argument("--getpid", type=int, default=64, help="getpid() calls per connect() [64]")
    p.add_argument("--label", default="", help="a name for this measurement in the output file")
    return p


def build_fixture(work):
    target = work.samples / "trace-cap-fixture"
    if not target.is_file():
        done = subprocess.run(["gcc", "-O2", "-static", "-Wall", "-Wextra", "-o", str(target), str(FIXTURE)],
                              capture_output=True, text=True, timeout=300)
        if done.returncode or not target.is_file():
            raise av.Failure(f"building the fixture failed: {done.stderr.strip()[-400:]}")
    return target


def stage_spans(events):
    """{stage: (started ts, finished ts)} from the run.stage events."""
    spans = {}
    for event in events:
        data = event.get("data") or {}
        if event.get("type") != "run.stage":
            continue
        stage, status, ts = data.get("stage"), data.get("status"), event.get("ts_ms")
        if status == "started":
            spans[stage] = (ts, None)
        elif status in ("finished", "failed", "skipped") and stage in spans:
            spans[stage] = (spans[stage][0], ts)
    return spans


def collect_parts(events):
    return [(e["data"].get("part"), e["data"].get("duration_ms"), e["data"].get("detail"))
            for e in events if e.get("type") == "run.collect"]


def file_before(job):
    directory = Path((job.get("recording") or {}).get("directory") or "/nonexistent")
    boot = (job.get("recording") or {}).get("boot_id")
    index = directory.parent.parent / "boots" / str(boot) / "file-before" / "index.json"
    try:
        return json.loads(index.read_text())
    except (OSError, ValueError):
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = parser().parse_args(argv)
    work, cli, accel, factor = av.preamble(args, __file__, argv, "T0612 trace cap")
    checks = av.Checks(work, f"T0612 collect after the trace cap ({args.cap_mib} MiB), TCG={accel == 'tcg'}")
    fixture = build_fixture(work)
    base_copy = work.copy_base(args.base)
    if args.dry_run:
        code = av.dry_run(work, cli, checks, [
            f"antinomie-cli base install {base_copy}", "antinomie-cli auto init --lane 1",
            f"service.toml: [resources] trace_cap_mib = {args.cap_mib}, min_free_disk_gib = 1",
            f"antinomie-cli auto submit {fixture.name} --timeout-run {args.run_s}",
            "auto status / auto events: the stage and collect times; file-before/index.json"])
        av.cleanup(work, keep=args.keep, say=checks.note)
        return code
    av.enter_vm_slot(args.vm_slot, __file__, argv)
    daemon = av.Daemon(cli, factor)
    watch = av.MemWatch(work, args.mem_floor_mb, daemon)
    watch.start()
    began = time.monotonic()
    summary = {"label": args.label, "cap_mib": args.cap_mib}
    try:
        base = av.install_base(cli, base_copy)
        checks.check(True, f"base {base['id'][:12]} installed ({base.get('label')}, revision {base.get('revision')})")
        lane = av.init_lane(cli, args, 1, factor=factor)
        checks.check(lane.get("snapshot_name") == "auto-clean", f"auto init: {lane.get('vm_name')}")
        toml = av.service_toml(lanes=1, require_kvm=accel == "kvm", min_free_disk_gib=1,
                               socket=work.socket_override())
        toml = av.set_toml_key(toml, "resources", "trace_cap_mib", str(int(args.cap_mib)))
        (work.data / "service.toml").write_text(toml)
        code, _, err = cli.run("config", "validate", timeout=300)
        checks.check(code == 0, "config validate exit 0" + ("" if code == 0 else f": {err.strip()[-300:]}"))
        daemon.start("trace-cap", args.mem_gate_mb)
        submitted = time.monotonic()
        job = av.submit(cli, fixture, timeout_run=args.run_s, name="trace-cap",
                        args=("--getpid", str(args.getpid), "--file", CHANGED_FILE))
        job = av.wait_job(cli, job["id"], JOB_TIMEOUT_S * factor, watch=watch, daemon=daemon, poll=2.0)
        summary["job_s"] = round(time.monotonic() - submitted, 1)
        codes = av.warning_codes(job)
        checks.check(job.get("state") == "partial" and "trace_cap_reached" in codes,
                     f"the job ended {job.get('state')} with trace_cap_reached ({', '.join(codes)})")
        for warning in job.get("warnings") or []:
            checks.note(f"warning {warning.get('code')}: {warning.get('text')}")
        events = av.events_of(cli, job["id"])
        spans = stage_spans(events)
        summary["stages_s"] = {stage: round((end - start) / 1000, 1) for stage, (start, end) in spans.items()
                               if start is not None and end is not None}
        checks.note("stages: " + ", ".join(f"{s} {t} s" for s, t in summary["stages_s"].items()))
        if "provision" in spans and "collect" in spans and spans["collect"][1]:
            held = (spans["collect"][1] - spans["provision"][0]) / 1000
            summary["vm_held_s"] = round(held, 1)
            summary["collect_s"] = round((spans["collect"][1] - spans["collect"][0]) / 1000, 1)
            checks.note(f"the lane held the VM {held:.1f} s; collect {summary['collect_s']} s")
        parts = collect_parts(events)
        summary["collect_parts"] = [{"part": p, "s": round((ms or 0) / 1000, 1), "detail": d} for p, ms, d in parts]
        for part, ms, detail in parts:
            checks.note(f"collect part {part}: {(ms or 0) / 1000:.1f} s ({detail})")
        names = [part for part, _, _ in parts]
        checks.check(all(name in names for name in ("evidence", "telemetry", "stop", "saving", "disk_layer")),
                     f"every collect part is timed ({', '.join(names)})")
        log = daemon.log_path.read_text(errors="replace") if daemon.log_path.is_file() else ""
        lines = [line for line in log.splitlines() if "collect took" in line or "earlier bytes" in line]
        summary["daemon_lines"] = lines
        checks.check(any("collect took" in line for line in lines), "the daemon log has the collect line")
        for line in lines:
            checks.note(f"daemon: {line}")
        summary["host_work"] = [{"name": i.get("name"), "state": i.get("state"),
                                 "s": round(((i.get("finished_ms") or 0) - (i.get("started_ms") or 0)) / 1000, 1)}
                                for i in job.get("host_work") or []]
        for item in summary["host_work"]:
            checks.note(f"host work {item['name']}: {item['state']} {item['s']} s")
        index = file_before(job)
        summary["file_before"] = index
        kept = [f for f in (index or {}).get("files") or [] if f.get("path") == CHANGED_FILE]
        checks.check(bool(index) and index.get("complete") and bool(kept),
                     f"the earlier bytes of {CHANGED_FILE} are kept "
                     f"(complete {None if index is None else index.get('complete')}, note "
                     f"{None if index is None else index.get('note')}, files "
                     f"{[f.get('path') for f in (index or {}).get('files') or []]})")
        for name, item in av.lane_list(cli).items():
            checks.check(not item.get("quarantine") and not item.get("busy_with") and not item.get("problems"),
                         f"{name} is free and clean after the job (problems {item.get('problems')})")
        code = daemon.stop()
        checks.check(code == 0, f"the daemon stopped on SIGTERM with exit {code}")
    except av.Failure as error:
        checks.check(False, f"stopped: {error}")
    finally:
        watch.stop()
        summary["elapsed_s"] = round(time.monotonic() - began, 1)
        name = f"trace-cap{'-' + args.label if args.label else ''}.json"
        (work.out / name).write_text(json.dumps(summary, indent=2) + "\n")
        checks.note(f"elapsed {summary['elapsed_s']} s; summary in {work.out / name}")
        av.cleanup(work, [daemon], args.keep, say=checks.note)
    return checks.summary()


if __name__ == "__main__":
    sys.exit(main())
