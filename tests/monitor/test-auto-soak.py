#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""T8 (design 7.2): the soak. Sequential benign Auto jobs for a set time.

One lane, `auto daemon`, a policy `soak` (shell scripts and ELF files, no
daily job limit) and retention set so that it has work to do within the run
(`[retention] recordings_days = 1`, `max_recordings_gib` = --recordings-cap-gib).
The jobs alternate between a behaviour sample (demo-recon, offline arguments)
and a short shell script, one at a time, until --duration has passed (or
--max-jobs ran). After each job it samples:

  fds, rss        the daemon's open file descriptors and resident memory
  threads         the daemon's threads
  snap_nodes      nodes in the lane VM's snapshots.json (the snapshot tree)
  vm_mib          the lane VM folder without its recordings (disk layers)
  service_mib     <data>/service (job store, events, artifacts)
  runs, runs_mib  the recordings kept
  over_cap_mib    recordings above max_recordings_gib
  gc_recordings   recordings `auto gc --dry-run` would delete now (beyond
                  retention, between the daemon's hourly passes)

and prints a growth table (first sample after --warmup jobs, last, change,
change per 100 jobs by a least-squares fit, the highest) with the p95 of each
stage's duration over the first and the last quarter of the jobs, then one
flat line. It does not call the result good or bad.

Stopping. SIGINT or SIGTERM (or MemAvailable below --max-mem-floor-mb, 2500
by default, or the daemon dying) stops it cleanly: no new job, the daemon
gets SIGTERM (a job in its VM stages is put back in the queue), the state is
kept in <work>/soak/ and the table so far is printed. `--resume` goes on
(the interrupted job first) until the soak has run --duration in all;
`--report` prints the table from the files without starting anything. The VM data is deleted
when the soak ends, and kept while it is stopped (resume needs it; --keep
keeps it at the end too; `--report --discard` deletes it).

    test-auto-soak.py --work DIR --base BASE --duration 24h [--resume|--report]

Exit 0 when the soak ran its time, 4 when it stopped early (resumable), 3 when
--work already holds a soak (or none to resume or report).
"""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import re
import signal
import sys
import time

spec = importlib.util.spec_from_file_location("auto_vm", Path(__file__).resolve().with_name("auto_vm.py"))
av = importlib.util.module_from_spec(spec)
sys.modules["auto_vm"] = av
spec.loader.exec_module(av)

STATE_VERSION = 1
JOB_TIMEOUT_S = 900
METRICS = ("fds", "rss_mib", "threads", "snap_nodes", "vm_mib", "service_mib", "runs", "runs_mib",
           "over_cap_mib", "gc_recordings")
SHELL = r"""
# T8 soak program (benign).
echo "soak $(uname -r)"
ls -l / > /dev/null
cat /proc/cpuinfo > /dev/null
sleep 3
echo "soak done"
"""


def duration(text):
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*", str(text))
    if not match:
        raise argparse.ArgumentTypeError("a duration such as 90m, 24h or 3600")
    return float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def parser():
    p = av.common_parser(__doc__, prog="test-auto-soak.py")
    p.add_argument("--duration", type=duration, default=duration("24h"), help="how long to submit jobs [24h]")
    p.add_argument("--max-jobs", type=int, default=None, help="stop after this many jobs as well")
    p.add_argument("--max-mem-floor-mb", dest="mem_floor_mb", type=int,
                   help="stop cleanly below this MemAvailable (the same as --mem-floor-mb) [2500]")
    p.add_argument("--warmup", type=int, default=10, help="jobs before the first sample of the table [10]")
    p.add_argument("--recordings-cap-gib", type=int, default=2, help="[retention] max_recordings_gib [2]")
    p.add_argument("--resume", action="store_true", help="go on with the soak kept in --work")
    p.add_argument("--report", action="store_true", help="print the table of the soak in --work and stop")
    p.add_argument("--discard", action="store_true", help="with --report: also delete its VM data")
    return p


# ------------------------------------------------------------ pure parts


def p95(values):
    ordered = sorted(v for v in values if v is not None)
    if not ordered:
        return None
    return ordered[min(len(ordered) - 1, max(0, math.ceil(0.95 * len(ordered)) - 1))]


def slope(xs, ys):
    """Least-squares change of y per unit of x; None for fewer than 2 points."""
    points = [(x, y) for x, y in zip(xs, ys) if x is not None and y is not None]
    if len(points) < 2:
        return None
    mean_x = sum(x for x, _ in points) / len(points)
    mean_y = sum(y for _, y in points) / len(points)
    spread = sum((x - mean_x) ** 2 for x, _ in points)
    if spread == 0:
        return None
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / spread


def growth_rows(samples, warmup):
    """[(metric, first, last, change, per_100_jobs, highest)] over the samples
    taken at or after `warmup` jobs."""
    used = [s for s in samples if s.get("jobs", 0) >= warmup] or samples[-1:]
    rows = []
    for metric in METRICS:
        values = [s.get(metric) for s in used]
        known = [v for v in values if v is not None]
        if not known:
            rows.append((metric, None, None, None, None, None))
            continue
        per = slope([s.get("jobs") for s in used], values)
        rows.append((metric, known[0], known[-1], known[-1] - known[0], None if per is None else per * 100,
                     max(known)))
    return rows


def stage_p95(jobs):
    """{stage: (p95 of the first quarter, p95 of the last quarter)} in seconds."""
    if not jobs:
        return {}
    quarter = max(1, len(jobs) // 4)
    first, last = jobs[:quarter], jobs[-quarter:]
    out = {}
    for stage in av.STAGES:
        a = p95([(j.get("stages") or {}).get(stage) for j in first])
        b = p95([(j.get("stages") or {}).get(stage) for j in last])
        if a is not None or b is not None:
            out[stage] = (None if a is None else a / 1000, None if b is None else b / 1000)
    return out


def number(value, digits=1):
    if value is None:
        return "-"
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.{digits}f}"
    return str(int(value))


def table(samples, jobs, warmup):
    lines = ["| Metric | First | Last | Change | Per 100 jobs | Highest |", "|---|---|---|---|---|---|"]
    for metric, first, last, change, per, high in growth_rows(samples, warmup):
        lines.append(f"| {metric} | {number(first)} | {number(last)} | {number(change)} | {number(per, 2)} "
                     f"| {number(high)} |")
    p95s = stage_p95(jobs)
    if p95s:
        lines += ["", "| Stage p95 (s) | First quarter | Last quarter |", "|---|---|---|"]
        lines += [f"| {stage} | {number(a, 2)} | {number(b, 2)} |" for stage, (a, b) in p95s.items()]
    return "\n".join(lines)


def outcomes(jobs):
    counts = {}
    for job in jobs:
        counts[job.get("state")] = counts.get(job.get("state"), 0) + 1
    return counts


def flat_line(state, samples, jobs, warmup):
    """One line: what ran and how the numbers moved; no adjective."""
    counts = outcomes(jobs)
    hours = (state.get("elapsed_s") or 0) / 3600
    rows = {row[0]: row for row in growth_rows(samples, warmup)}

    def move(metric, unit=""):
        row = rows.get(metric)
        if not row or row[1] is None:
            return f"{metric} -"
        return f"{metric} {number(row[1])}->{number(row[2])}{unit}"

    failed = sum(v for k, v in counts.items() if k not in ("succeeded", "partial"))
    host_only = sum(1 for j in jobs if j.get("state") == "partial" and j.get("host_tools_only"))
    p95s = stage_p95(jobs)
    run = p95s.get("run", (None, None))
    return (f"soak: {len(jobs)} jobs in {hours:.1f} h ({', '.join(f'{k} {v}' for k, v in sorted(counts.items()))}; "
            f"partial for host tools only {host_only}; not succeeded/partial {failed}); "
            + "; ".join(move(m) for m in ("fds", "rss_mib", "threads", "snap_nodes", "vm_mib", "service_mib",
                                         "runs_mib", "over_cap_mib", "gc_recordings"))
            + f"; p95 run {number(run[0], 2)}->{number(run[1], 2)} s; ended: {state.get('stop_reason') or state.get('phase')}")


# ------------------------------------------------------------ files


class Soak:
    def __init__(self, work):
        self.dir = work.root / "soak"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / "state.json"
        self.jobs_path = self.dir / "jobs.ndjson"
        self.samples_path = self.dir / "samples.ndjson"

    def state(self):
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return None

    def save(self, state):
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(state, indent=2) + "\n")
        temp.replace(self.state_path)

    def append(self, path, record):
        with open(path, "a") as file:
            file.write(json.dumps(record, sort_keys=True) + "\n")

    @staticmethod
    def read(path):
        out = []
        if path.is_file():
            for line in path.read_text().splitlines():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass  # a line cut by a stop
        return out

    def report(self, warmup, say=print):
        state = self.state() or {}
        jobs, samples = self.read(self.jobs_path), self.read(self.samples_path)
        text = table(samples, jobs, warmup) + "\n\n" + flat_line(state, samples, jobs, warmup)
        (self.dir / "report.md").write_text(text + "\n")
        say(text)
        return text


# ------------------------------------------------------------ sampling


def gc_recordings(cli):
    code, parsed, _ = cli.run("auto", "gc", "--dry-run", daemon=True, timeout=300)
    result = av.unwrap(parsed) if code == 0 else None
    if not isinstance(result, dict):
        return None
    return sum(1 for action in result.get("actions") or [] if action.get("kind") == "recording")


def sample(work, cli, daemon, vm_id, cap_gib, jobs):
    pid = daemon.pid if daemon.alive() else None
    vm_dir = work.data / vm_id
    try:
        nodes = len(json.loads((vm_dir / "snapshots.json").read_text()).get("nodes") or [])
    except (OSError, ValueError):
        nodes = None
    run_dirs = [d for d in work.data.glob("*/runs/*") if d.is_dir()]
    runs_bytes = sum(av.tree_bytes(d) for d in run_dirs)
    return {"t": round(time.time(), 1), "jobs": jobs, "mem_available_mb": av.mem_available_mb(),
            "fds": av.open_fds(pid) if pid else None,
            "rss_mib": round(av.status_kib(pid, "VmRSS") / 1024, 1) if pid else None,
            "threads": av.status_kib(pid, "Threads") if pid else None,
            "snap_nodes": nodes, "vm_mib": round(av.tree_bytes(vm_dir, skip=("runs",)) / av.MIB, 1),
            "service_mib": round(av.tree_bytes(work.data / "service") / av.MIB, 1),
            "runs": len(run_dirs), "runs_mib": round(runs_bytes / av.MIB, 1),
            "over_cap_mib": round(max(0, runs_bytes - cap_gib * av.GIB) / av.MIB, 1),
            "gc_recordings": gc_recordings(cli) if pid else None}


# ------------------------------------------------------------ the run


class Stop:
    def __init__(self):
        self.reason = None

    def __call__(self, signum, _frame):
        self.reason = self.reason or f"signal {signal.Signals(signum).name}"


def setup(cli, work, args, accel, factor, soak):
    base = av.install_base(cli, work.copy_base(args.base))
    lane = av.init_lane(cli, args, 1, factor=factor)
    (work.data / "service.toml").write_text(av.service_toml(
        lanes=1, require_kvm=accel == "kvm",
        retention={"recordings_days": 1, "max_recordings_gib": args.recordings_cap_gib},
        socket=work.socket_override()))
    av.edit_policy(work, "soak", {("sample", "accept_types"): '["elf", "sh"]',
                                  ("limits", "max_jobs_per_day"): "1000000"})
    code, _, err = cli.run("config", "validate", timeout=300)
    if code != 0:
        raise av.Failure(f"config validate exit {code}: {err.strip()[-300:]}")
    now = time.time()
    state = {"version": STATE_VERSION, "phase": "running", "started": now, "deadline": now + args.duration,
             "duration_s": args.duration, "max_jobs": args.max_jobs, "accel": accel, "base": base["id"],
             "vm_id": lane["vm_id"], "jobs": 0, "pending_job": None, "elapsed_s": 0, "stop_reason": None,
             "stops": 0}
    soak.save(state)
    return state


def record_job(cli, soak, state, job, number):
    events = av.events_of(cli, job["id"])
    ok, why = av.outcome_ok(job)
    record = {"n": number, "id": job["id"], "state": job.get("state"), "ok": ok, "why": why,
              "host_tools_only": job.get("state") == "partial" and ok,
              "failure": (job.get("failure") or {}).get("code"), "warnings": sorted(set(av.warning_codes(job))),
              "attempt": job.get("attempt"), "created_ms": job.get("created_ms"),
              "finished_ms": job.get("finished_ms"), "stages": av.stage_durations(events)}
    soak.append(soak.jobs_path, record)
    return record


def soak_loop(cli, work, args, factor, soak, state, daemon, watch, stop, programs):
    def stopped():
        if watch.tripped:
            stop.reason = stop.reason or watch.tripped
        if not daemon.alive():
            stop.reason = stop.reason or f"the daemon exited {daemon.process.returncode}"
        return stop.reason

    def wait(job_id):
        deadline = time.monotonic() + JOB_TIMEOUT_S * factor
        while time.monotonic() < deadline:
            if stopped():
                return None
            job = av.job_status(cli, job_id)
            if av.is_terminal(job):
                return job
            time.sleep(5)
        raise av.Failure(f"job {job_id} did not end within {JOB_TIMEOUT_S * factor:.0f} s")

    began = time.monotonic()
    base_elapsed = state.get("elapsed_s") or 0
    while not stopped():
        if state.get("pending_job"):
            job_id = state["pending_job"]
        else:
            if time.time() >= state["deadline"] or (state.get("max_jobs") and state["jobs"] >= state["max_jobs"]):
                state["phase"] = "done"
                break
            if av.mem_available_mb() < args.mem_floor_mb:
                stop.reason = f"MemAvailable {av.mem_available_mb()} MB below the floor of {args.mem_floor_mb} MB"
                break
            program, extra = programs[state["jobs"] % len(programs)]
            job_id = av.submit(cli, program, policy="soak", timeout_run=60, name=f"soak-{state['jobs'] + 1}",
                               args=extra)["id"]
            state["pending_job"] = job_id
            soak.save(state)
        job = wait(job_id)
        if job is None:
            break
        state["jobs"] += 1
        record = record_job(cli, soak, state, job, state["jobs"])
        state["pending_job"] = None
        state["elapsed_s"] = base_elapsed + (time.monotonic() - began)
        soak.append(soak.samples_path, sample(work, cli, daemon, state["vm_id"], args.recordings_cap_gib,
                                              state["jobs"]))
        soak.save(state)
        if state["jobs"] % 10 == 0 or not record["ok"]:
            left = max(0, state["deadline"] - time.time()) / 3600
            print(f"     job {state['jobs']}: {record['why']}; {left:.1f} h left", flush=True)
    state["elapsed_s"] = base_elapsed + (time.monotonic() - began)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = parser().parse_args(argv)
    if args.mem_floor_mb is None:
        args.mem_floor_mb = 2500
    work, cli, accel, factor = av.preamble(args, __file__, argv, "T8 soak")
    soak = Soak(work)
    previous = soak.state()
    if args.report:
        if not previous:
            print(f"no soak in {work.root}")
            return 3
        soak.report(args.warmup)
        if args.discard:
            av.cleanup(work, keep=False)
        return 0
    if previous and not args.resume:
        print(f"a soak ({previous.get('phase')}, {previous.get('jobs')} jobs) is kept in {soak.dir}: pass --resume "
              "to go on, --report to print it, or remove the folder")
        return 3
    if args.resume and (not previous or previous.get("phase") == "done"):
        print(f"nothing to resume in {soak.dir} ({previous and previous.get('phase')})")
        return 3
    checks = av.Checks(work, f"T8 soak, {args.duration / 3600:g} h, TCG={accel == 'tcg'}")
    sample_program = av.build_sample(work, "recon")
    shell = av.write_guest_script(work.samples / "soak.sh", SHELL)
    programs = [(sample_program, av.SAMPLE_ARGS), (shell, ())]
    if args.dry_run:
        code = av.dry_run(work, cli, checks, [
            "base install; auto init; service.toml lanes = 1, [retention] recordings_days = 1, "
            f"max_recordings_gib = {args.recordings_cap_gib}; policy soak (elf, sh; max_jobs_per_day 1000000)",
            f"auto daemon; one job at a time for {args.duration / 3600:g} h"
            + (f" or {args.max_jobs} jobs" if args.max_jobs else "") + f": {sample_program.name} and {shell.name}",
            "after each job: events, sample of " + ", ".join(METRICS), "table + flat line; delete the VM data"])
        av.cleanup(work, keep=args.keep, say=checks.note)
        return code
    av.enter_vm_slot(args.vm_slot, __file__, argv)
    stop = Stop()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    daemon = av.Daemon(cli, factor)
    watch = av.MemWatch(work, args.mem_floor_mb, daemon)
    watch.start()
    state = previous
    try:
        if not args.resume:
            state = setup(cli, work, args, accel, factor, soak)
        else:
            state["phase"], state["stop_reason"] = "running", None
            state["stops"] = (state.get("stops") or 0) + 1
            state["deadline"] = time.time() + max(0.0, state["duration_s"] - (state.get("elapsed_s") or 0))
            if not (work.data / "service.toml").is_file():
                raise av.Failure(f"the soak's data folder {work.data} is gone; it cannot be resumed")
        daemon.start("soak", args.mem_gate_mb)
        soak.append(soak.samples_path, sample(work, cli, daemon, state["vm_id"], args.recordings_cap_gib,
                                              state["jobs"]))
        soak_loop(cli, work, args, factor, soak, state, daemon, watch, stop, programs)
    except av.Failure as error:
        stop.reason = stop.reason or f"stopped: {error}"
    finally:
        watch.stop()
        if daemon.alive():
            code = daemon.stop()
            checks.note(f"daemon stopped with {code}")
        if state:
            if state.get("phase") != "done":
                state["phase"], state["stop_reason"] = "stopped", stop.reason or "stopped"
            soak.save(state)
    soak.report(args.warmup, say=checks.say)
    if state and state.get("phase") == "done":
        av.cleanup(work, [daemon], args.keep, say=checks.note)
        return 0
    checks.say(f"soak stopped ({state and state.get('stop_reason')}); the VM data stays for --resume in {work.root}")
    return 4


if __name__ == "__main__":
    sys.exit(main())
