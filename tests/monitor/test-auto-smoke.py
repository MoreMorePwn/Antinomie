#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""T5 (design 7.2): one full Auto job on a real VM.

A benign behaviour sample (tests/monitor/behavior-samples, demo-recon by
default, with offline arguments) goes through every stage: boot and revert
(provision), upload, launch, run, collect, analyse, report, cleanup, under
`auto daemon` on a lane made by `auto init`. The script checks the job
object, its events, the host work items, the report files (fetched and their
SHA-256 compared), report.json, the run and the custody chain, and that the
lane is clean afterwards. With --lanes 2 a second lane is made
(`auto init --lane 2`, `[daemon] lanes = 2`), two jobs run and each lane must
take one, its run kept in its own lane folder.

    test-auto-smoke.py --work DIR --base BASE [--lanes 2] [--vm-slot PREFIX]

A partial job whose only warnings say a host tool was missing
(static_check_incomplete, detection_skipped) counts as a pass and is listed;
--strict asks for `succeeded`. Exit 0 when every check holds, 1 otherwise.
"""
import importlib.util
from pathlib import Path
import json
import sys
import time

spec = importlib.util.spec_from_file_location("auto_vm", Path(__file__).resolve().with_name("auto_vm.py"))
av = importlib.util.module_from_spec(spec)
sys.modules["auto_vm"] = av
spec.loader.exec_module(av)

CUSTODY_KINDS = ("added", "sent", "run_started", "run_ended")
JOB_TIMEOUT_S = 900  # one job, submit to end, at KVM speed


def parser():
    p = av.common_parser(__doc__, prog="test-auto-smoke.py")
    p.add_argument("--lanes", type=int, choices=(1, 2), default=1, help="lanes to run [1]")
    p.add_argument("--jobs", type=int, default=None, help="jobs to submit [one per lane]")
    p.add_argument("--scenario", default="recon", help="the behaviour sample demo-SCENARIO [recon]")
    p.add_argument("--strict", action="store_true", help="a partial job fails the check")
    return p


def plan(args, sample, base_copy):
    jobs = args.jobs or args.lanes
    steps = [f"antinomie-cli base install {base_copy}"]
    steps += [f"antinomie-cli auto init --lane {n} --ram-mib {args.ram_mib} --cpus {args.cpus} "
              f"--disk-gib {args.disk_gib}"
              + (" --password-stdin (a random password of this run)" if args.random_guest_password else "")
              for n in range(1, args.lanes + 1)]
    steps += [f"service.toml: [daemon] lanes = {args.lanes}; [resources] require_kvm per --accel",
              "antinomie-cli config validate",
              "antinomie-cli auto daemon (recorded PID; MemAvailable watched every 2 s)",
              f"{jobs} x antinomie-cli auto submit {sample.name} --timeout-run 60 --args {' '.join(av.SAMPLE_ARGS)}",
              "per job: auto status, auto events, auto fetch html/json, recording list --run, sample show --events, "
              "custody verify",
              "auto lane list; SIGTERM the daemon; delete the VM data"]
    return steps


def custody_checks(cli, sha):
    shown = cli.ok("sample", "show", sha, "--events", daemon=True, timeout=120)
    kinds = [event.get("kind") for event in shown.get("events") or []]
    verified = cli.ok("custody", "verify", sha, daemon=True, timeout=120)
    return [(all(kind in kinds for kind in CUSTODY_KINDS),
             f"custody of {sha[:12]} has {', '.join(CUSTODY_KINDS)} (has {', '.join(kinds)})"),
            (verified.get("ok") is True, f"custody verify: {verified.get('summary')}")]


def verify_job(cli, work, checks, job, lanes, base, strict):
    lane = job.get("lane")
    info = lanes.get(lane) or {}
    prefix = f"[{job['id'][-8:]} {lane}] "
    checks.all(av.job_checks(job, vm_name=info.get("vm_name"), base_identity=base["id"], strict=strict), prefix)
    for warning in job.get("warnings") or []:
        checks.note(f"{prefix}warning {warning.get('code')}: {warning.get('text')}")
    folder = work.lane_dir(int(str(lane).rpartition("-")[2] or 1)) if lane else work.data
    directory = Path((job.get("recording") or {}).get("directory") or "/nonexistent")
    inside = directory.is_dir() and folder in directory.parents
    if lane == "lane-1":
        inside = inside and (work.data / "lanes") not in directory.parents
    checks.check(inside, f"{prefix}the recording is in {lane}'s folder ({directory})")
    events = av.events_of(cli, job["id"])
    problems = av.event_problems(events)
    checks.check(not problems, f"{prefix}{len(events)} events in order" + ("; " + "; ".join(problems) if problems else ""))
    durations = av.stage_durations(events)
    checks.note(prefix + "stages: " + ", ".join(f"{s} {durations[s] / 1000:.1f} s" for s in av.STAGES if s in durations))
    artifacts = {a.get("kind"): a for a in job.get("artifacts") or []}
    for kind in ("html", "json"):
        artifact = artifacts.get(f"report.{kind}") or {}
        path = av.fetch_artifact(cli, job["id"], kind, work.out / "reports" / job["id"])
        same = path.is_file() and path.stat().st_size == artifact.get("size") and av.sha256_file(path) == artifact.get("sha256")
        checks.check(same, f"{prefix}auto fetch {kind}: {path.name}, size and SHA-256 as the artifact says")
        if kind == "json" and path.is_file():
            try:
                checks.all(av.report_json_checks(json.loads(path.read_text()), job), prefix)
            except ValueError as error:
                checks.check(False, f"{prefix}report.json parses: {error}")
    runs = cli.ok("recording", "list", "--run", job["id"], daemon=True, timeout=120).get("items", [])
    run_id = (job.get("program") or {}).get("id")
    checks.check([r.get("run_id") for r in runs] == [run_id], f"{prefix}recording list --run finds the recording {str(run_id)[:12]}")
    checks.all(custody_checks(cli, job["sample"]["sha256"]), prefix)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = parser().parse_args(argv)
    work, cli, accel, factor = av.preamble(args, __file__, argv, "T5 smoke")
    checks = av.Checks(work, f"T5 Auto smoke, {args.lanes} lane(s), TCG={accel == 'tcg'}")
    sample = av.build_sample(work, args.scenario)
    base_copy = work.copy_base(args.base)
    if args.dry_run:
        code = av.dry_run(work, cli, checks, plan(args, sample, base_copy))
        av.cleanup(work, keep=args.keep, say=checks.note)
        return code
    av.enter_vm_slot(args.vm_slot, __file__, argv)
    daemon = av.Daemon(cli, factor)
    watch = av.MemWatch(work, args.mem_floor_mb, daemon)
    watch.start()
    began = time.monotonic()
    try:
        base = av.install_base(cli, base_copy)
        checks.check(True, f"base {base['id'][:12]} installed ({base.get('label')}, revision {base.get('revision')})")
        lanes = {}
        for number in range(1, args.lanes + 1):
            start = time.monotonic()
            info = av.init_lane(cli, args, number, factor=factor)
            lanes[f"lane-{number}"] = info
            checks.check(info.get("snapshot_name") == "auto-clean" and info.get("base_identity") == base["id"],
                         f"auto init --lane {number}: {info.get('vm_name')} and its clean snapshot "
                         f"in {time.monotonic() - start:.0f} s (first boot {info.get('boot_ms')} ms)")
        (work.data / "service.toml").write_text(av.service_toml(lanes=args.lanes, require_kvm=accel == "kvm",
                                                                    socket=work.socket_override()))
        code, _, err = cli.run("config", "validate", timeout=300)
        checks.check(code == 0, "config validate exit 0" + ("" if code == 0 else f": {err.strip()[-300:]}"))
        status = daemon.start("smoke", args.mem_gate_mb)
        started = [lane.get("lane") for lane in status.get("lanes") or []]
        checks.check(sorted(started) == sorted(lanes), f"the daemon runs {', '.join(started)}")
        jobs = [av.submit(cli, sample, timeout_run=60, name=f"smoke-{n}", args=av.SAMPLE_ARGS)
                for n in range(1, (args.jobs or args.lanes) + 1)]
        finished = [av.wait_job(cli, job["id"], JOB_TIMEOUT_S * factor * len(jobs), watch=watch, daemon=daemon)
                    for job in jobs]
        for job in finished:
            verify_job(cli, work, checks, job, lanes, base, args.strict)
        if args.lanes == 2:
            used = sorted({job.get("lane") for job in finished})
            checks.check(used == ["lane-1", "lane-2"], f"the jobs spread over the lanes: {used}")
        for name, lane in av.lane_list(cli).items():
            checks.check(not lane.get("quarantine") and not lane.get("busy_with") and lane.get("failures") == 0
                         and not lane.get("problems"),
                         f"{name} is free and clean after the jobs (quarantine {lane.get('quarantine')}, "
                         f"problems {lane.get('problems')})")
        code = daemon.stop()
        checks.check(code == 0, f"the daemon stopped on SIGTERM with exit {code}")
    except av.Failure as error:
        checks.check(False, f"stopped: {error}")
    finally:
        watch.stop()
        checks.note(f"elapsed {time.monotonic() - began:.0f} s; minimum MemAvailable {watch.minimum} MB "
                    f"(see {work.out / 'mem.log'})")
        av.cleanup(work, [daemon], args.keep, say=checks.note)
    return checks.summary()


if __name__ == "__main__":
    sys.exit(main())
