#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""T7 (design 7.2, failure matrix 4.7.3): faults injected into real Auto jobs.

Each case runs in a folder of its own (<work>/cases/<case>/) with its own
copy of the base, its own lane VM (`auto init`) and `auto daemon`, and states
the job state it expects. Only recorded PIDs are signalled: the daemon the
harness started, and the lane's QEMU as service/lanes/lane-1.json records it
(PID, start time and command line checked first).

  qemu-kill       SIGKILL the lane's QEMU in the run stage of a 45 s benign
                  program. Expected: attempt 1 ends guest_lost and is retried
                  (job.requeued); the job ends succeeded (or partial for host
                  tools only) on attempt 2; the lane is not quarantined.
  daemon-kill     SIGKILL the daemon in the run stage, then start it again.
                  Expected: recovery ends the recorded QEMU, requeues the job
                  (job.requeued, service_restart, the first restart free) and
                  it ends succeeded or partial (host tools); the lane is free.
  disk-full       The data folder on a small filesystem: a tmpfs of
                  --quota-mib in a user and mount namespace of this script
                  (unshare --user --map-current-user --mount; no root), or
                  --quota-dir, a mount point below --work. With
                  min_free_disk_gib = 1 and the engine's quota_gib = 1 (the
                  daemon admits a job with the floor plus that capture quota
                  free, 2 GiB; the default 4 GiB would need 5): (a) filled
                  to below the floor, a job
                  waits queued (waiting_for resources, or queue_paused with
                  the queue paused low_disk) and runs when the space is back; (b) filled to
                  ENOSPC in the run stage, the queue pauses low_disk (held in
                  memory when the job store is full too), the job ends partial
                  or failed once the space is freed (it does not hang), the
                  daemon stays up, the next job ends succeeded or partial
                  (host tools), and the daemon exits 0 on SIGTERM.
  guest-panic     A benign program run as root writes `c` to
                  /proc/sysrq-trigger. Expected: each attempt loses the guest
                  (guest_lost), one retry, the job ends failed with
                  guest_lost; the lane is not quarantined and the next benign
                  job ends succeeded or partial (host tools).
  revert-corrupt  The clean snapshot's disk layer of this case's own lane VM
                  is overwritten at its start (daemon stopped). Expected: the
                  restore fails and is retried once, the job ends failed with
                  revert_failed, lane-1 is quarantined (revert_failed) and a
                  second queued job waits with waiting_for lane_quarantined
                  (then it is cancelled).

    test-auto-faults.py --work DIR --base BASE [--case qemu-kill,...]

Prints a table of each case: expected, observed, whether it held. Exit 0
when every case held, 1 otherwise.
"""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("auto_vm", Path(__file__).resolve().with_name("auto_vm.py"))
av = importlib.util.module_from_spec(spec)
sys.modules["auto_vm"] = av
spec.loader.exec_module(av)

JOB_TIMEOUT_S = 900
LONG = r"""
# T7 long program (benign): 45 one-second ticks.
i=0
while [ "$i" -lt 45 ]; do echo "t7 tick $i"; sleep 1; i=$((i + 1)); done
echo "t7 done"
"""
LONGER = LONG.replace("45", "150")
SHORT = r"""
# T7 short program (benign).
echo "t7 short $(uname -r)"
ls / > /dev/null
sleep 2
"""
PANIC = r"""
# T7 guest panic (benign to the host): the guest kernel crashes on request.
echo "t7 asking the guest kernel to crash"
sync
echo c > /proc/sysrq-trigger
sleep 30
"""
EXPECTED = {
    "qemu-kill": "attempt 1 guest_lost, retried (job.requeued); ends succeeded/partial(host tools) on attempt 2; "
                 "lane not quarantined",
    "daemon-kill": "recovery ends the recorded QEMU, job.requeued (service_restart); ends succeeded/partial(host "
                   "tools); lane free",
    "disk-full": "(a) below the floor: queued, waiting_for resources, then runs; (b) ENOSPC mid-run: queue paused "
                 "low_disk, then partial or failed, daemon up; next job succeeded/partial(host tools); SIGTERM exit 0",
    "guest-panic": "guest_lost on each attempt, one retry, ends failed guest_lost; lane not quarantined; next job ok",
    "revert-corrupt": "restore retried once, failed revert_failed, lane-1 quarantined revert_failed, the next job "
                      "waits lane_quarantined",
}
CASES = tuple(EXPECTED)
# disk-full: the floor (service.toml) and the capture quota (settings.json
# quota_gib, its minimum). The daemon admits a job only with floor + quota
# GiB free on the data folder (antinomie-service resources.rs).
DISK_FLOOR_GIB = 1
DISK_QUOTA_GIB = 1
POLICY = {("sample", "accept_types"): '["elf", "sh"]', ("run", "allow_root"): "true",
          ("retry", "backoff_s"): "[10, 10]"}


def cases(text):
    chosen = [c.strip() for c in text.split(",") if c.strip()]
    unknown = [c for c in chosen if c not in CASES]
    if unknown or not chosen:
        raise SystemExit(f"--case takes {', '.join(CASES)}; got {text!r}")
    return chosen


def parser():
    p = av.common_parser(__doc__, prog="test-auto-faults.py")
    p.add_argument("--case", type=cases, default=list(CASES), help=f"cases, in order [{','.join(CASES)}]")
    p.add_argument("--quota-mib", type=int, default=2560,
                   help="disk-full: size of the tmpfs quota; it must hold the floor plus the capture quota "
                        "(2 GiB) and the case's data [2560]")
    p.add_argument("--quota-dir", type=Path, default=None,
                   help="disk-full: an existing small filesystem mounted below --work, instead of the tmpfs")
    p.add_argument("--quota-inner", type=Path, default=None, help=argparse.SUPPRESS)
    return p


def without_option(argv, name):
    """argv without `name VALUE` and `name=VALUE`."""
    out, skip = [], False
    for item in argv:
        if skip:
            skip = False
        elif item == name:
            skip = True
        elif not item.startswith(name + "="):
            out.append(item)
    return out


def quota_argv(script, argv, mount, size_mib, python):
    """The namespace that gives disk-full a small filesystem without root:
    a tmpfs mounted in a user+mount namespace of this script, then the
    capabilities dropped before the harness runs in it again."""
    inner = [python, "-I", str(script), *without_option(without_option(argv, "--case"), "--quota-inner"),
             "--case", "disk-full", "--quota-inner", str(mount)]
    shell = (f"mount -t tmpfs -o size={int(size_mib)}m,mode=0700 antinomie-quota {shlex.quote(str(mount))} && "
             f"exec setpriv --inh-caps=-all --ambient-caps=-all {shlex.join(inner)}")
    return ["unshare", "--user", "--map-current-user", "--mount", "--keep-caps", "sh", "-c", shell]


def snapshot_disk(manifest, snapshot_id):
    """The disk layer file (relative to the VM folder) of a snapshot in the
    VM's snapshots.json."""
    for node in manifest.get("nodes") or []:
        if (node.get("checkpoint") or {}).get("id") == snapshot_id:
            return node.get("disk")
    return None


def fill(path, leave_bytes, chunk=64 * av.MIB, free=None):
    """Write zeros into path until the filesystem has at most leave_bytes
    free, or until it is full (ENOSPC) when leave_bytes is 0; the bytes
    written. `free(folder)` gives the free bytes (statvfs by default)."""
    free = free or (lambda folder: shutil.disk_usage(folder).free)
    written = 0
    with open(path, "ab") as file:
        while True:
            room = free(path.parent) - leave_bytes
            if room <= 0:
                break
            size = min(chunk, room) if leave_bytes else chunk
            try:
                file.write(b"\0" * size)
                file.flush()
                os.fsync(file.fileno())
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                break
            written += size
    return written


class Case:
    """One case's folder, CLI, daemon and memory watch."""

    def __init__(self, args, name, factor, accel, data=None, data_root=None):
        self.args, self.name, self.factor, self.accel = args, name, factor, accel
        self.work = av.Work(Path(args.work) / "cases" / name).prepare()
        self.data_root = Path(data_root) if data_root else self.work.root
        if data:
            self.work.data = Path(data)
        self.cli = av.Cli(args.cli, self.work, accel, args.tcg_multiplier)
        self.daemon = av.Daemon(self.cli, factor)
        self.watch = av.MemWatch(self.work, args.mem_floor_mb, self.daemon)
        self.lane = None

    def setup(self, min_free_disk_gib=None, quota_gib=None):
        av.install_base(self.cli, self.work.copy_base(self.args.base))
        self.lane = av.init_lane(self.cli, self.args, 1, factor=self.factor)
        if quota_gib is not None:
            self.cli.ok("config", "set", "quota_gib", quota_gib, timeout=120)
        (self.work.data / "service.toml").write_text(
            av.service_toml(lanes=1, require_kvm=self.accel == "kvm", min_free_disk_gib=min_free_disk_gib,
                            socket=self.work.socket_override()))
        av.edit_policy(self.work, "t7", POLICY)
        code, _, err = self.cli.run("config", "validate", timeout=300)
        if code != 0:
            raise av.Failure(f"config validate exit {code}: {err.strip()[-300:]}")

    def program(self, name, body):
        return av.write_guest_script(self.work.samples / f"{name}.sh", body)

    def submit(self, program, **kwargs):
        return av.submit(self.cli, program, policy="t7", timeout_run=kwargs.pop("timeout_run", 120), **kwargs)

    def wait(self, job, until=av.is_terminal, timeout=JOB_TIMEOUT_S):
        return av.wait_job(self.cli, job["id"], timeout * self.factor, until=until, watch=self.watch,
                           daemon=self.daemon)

    def requeues(self, job):
        return [e.get("data") or {} for e in av.events_of(self.cli, job["id"]) if e.get("type") == "job.requeued"]

    def lane_state(self):
        return av.lane_list(self.cli).get("lane-1") or {}

    def qemu_record(self):
        return (self.work.read_lane_file(1) or {}).get("qemu")

    def finish(self):
        self.watch.stop()
        return av.cleanup(self.work, [self.daemon], self.args.keep, data_folders=[self.work.data], say=print,
                          data_root=self.data_root)


def describe(job):
    failure = job.get("failure") or {}
    return (f"{job.get('state')}{' ' + failure.get('code') if failure.get('code') else ''} "
            f"attempt {job.get('attempt')}/{job.get('max_attempts')}")


def case_qemu_kill(case):
    case.daemon.start(case.name, case.args.mem_gate_mb)
    job = case.submit(case.program("long", LONG))
    case.wait(job, until=av.in_stage("run"))
    time.sleep(5)
    record = case.qemu_record()
    if not av.kill_recorded(record):
        raise av.Failure(f"no live recorded QEMU in lane-1.json at the run stage ({record})")
    print(f"     killed the recorded QEMU {record['pid']} (start ticks {record.get('start_ticks')})", flush=True)
    job = case.wait(job)
    requeued = case.requeues(job)
    lane = case.lane_state()
    holds = (av.outcome_ok(job)[0] and (job.get("attempt") or 0) >= 2 and bool(requeued)
             and not lane.get("quarantine"))
    return holds, f"{describe(job)}; requeued {[r.get('reason') for r in requeued]}; quarantine {lane.get('quarantine')}"


def case_daemon_kill(case):
    case.daemon.start(case.name, case.args.mem_gate_mb)
    owner = case.daemon.owner_pid()
    job = case.submit(case.program("long", LONG))
    case.wait(job, until=av.in_stage("run"))
    time.sleep(5)
    record = case.qemu_record()
    if owner not in (None, case.daemon.pid):
        raise av.Failure(f"run/owner.json names PID {owner}, not the daemon started ({case.daemon.pid})")
    case.daemon.kill()
    orphan = av.recorded_alive(record)
    print(f"     SIGKILL to the daemon {case.daemon.pid}; its QEMU {record and record.get('pid')} "
          f"{'still runs' if orphan else 'is gone'}", flush=True)
    case.daemon.start(case.name + " after SIGKILL", case.args.mem_gate_mb)
    deadline = time.monotonic() + 120 * case.factor
    while av.recorded_alive(record) and time.monotonic() < deadline:
        time.sleep(2)
    left = av.recorded_alive(record)
    job = case.wait(job)
    requeued = case.requeues(job)
    lane = case.lane_state()
    holds = (av.outcome_ok(job)[0] and bool(requeued) and not left and not lane.get("quarantine")
             and not lane.get("busy_with"))
    return holds, (f"{describe(job)}; old QEMU after restart {'ALIVE' if left else 'gone'}; requeued "
                   f"{[r.get('reason') for r in requeued]}; quarantine {lane.get('quarantine')}")


def queue(case):
    return case.cli.ok("auto", "status", daemon=True, timeout=120)


def case_disk_full_inner(case):
    # The filler lives on the small filesystem next to the data folder.
    filler = case.work.data.parent / "filler.bin"
    try:
        return disk_full_steps(case, filler)
    finally:
        filler.unlink(missing_ok=True)


def floor_wait(job):
    return av.is_terminal(job) or job.get("waiting_for") in ("resources", "queue_paused")


def disk_full_steps(case, filler):
    free = shutil.disk_usage(filler.parent).free
    needed = (DISK_FLOOR_GIB + DISK_QUOTA_GIB) * av.GIB + 256 * av.MIB
    if free < needed:
        raise av.Failure(f"the quota filesystem has {free // av.MIB} MiB free after the setup; a job is admitted "
                         f"only with {DISK_FLOOR_GIB + DISK_QUOTA_GIB} GiB free (floor + capture quota): "
                         f"raise --quota-mib or use a larger --quota-dir")
    case.daemon.start(case.name, case.args.mem_gate_mb)
    observed, holds = [], True
    # (a) below the floor before the job
    fill(filler, 512 * av.MIB)
    time.sleep(10)
    job = case.submit(case.program("short-a", SHORT))
    waiting = case.wait(job, until=floor_wait, timeout=180)
    paused = queue(case)
    holds &= waiting.get("waiting_for") == "resources" or (
        waiting.get("waiting_for") == "queue_paused" and paused.get("pause_reason") == "low_disk")
    observed.append(f"(a) {waiting.get('state')} waiting_for {waiting.get('waiting_for')}, queue paused "
                    f"{paused.get('paused')} {paused.get('pause_reason')}")
    filler.unlink()
    job = case.wait(job)
    holds &= av.outcome_ok(job)[0]
    observed.append(f"then {describe(job)}")
    # (b) ENOSPC in the run stage
    job = case.submit(case.program("long-b", LONGER), timeout_run=240)
    case.wait(job, until=av.in_stage("run"))
    time.sleep(5)
    written = fill(filler, 0)
    print(f"     filled the quota with {written // av.MIB} MiB, {shutil.disk_usage(filler.parent).free} bytes free",
          flush=True)
    # The floor stops the run within a minute and pauses the queue (low_disk).
    # The job store may be unable to take the job's end while the disk is
    # full: the job then waits for room with the queue paused, so the space is
    # freed once the job is over or the pause is seen.
    seen = {}

    def over_or_paused(j):
        if av.is_terminal(j):
            return True
        seen.update(queue(case))
        return seen.get("pause_reason") == "low_disk"

    job = case.wait(job, until=over_or_paused)
    paused = queue(case) if av.is_terminal(job) else seen
    holds &= paused.get("pause_reason") == "low_disk" and case.daemon.alive()
    observed.append(f"(b) full: {job.get('state')} {job.get('stage') or ''}, queue paused {paused.get('paused')} "
                    f"{paused.get('pause_reason')}")
    filler.unlink()
    job = case.wait(job)
    holds &= job.get("state") in ("partial", "failed") and case.daemon.alive()
    observed.append(f"then {describe(job)} warnings {sorted(set(av.warning_codes(job)))}; end_reason "
                    f"{(job.get('run') or {}).get('end_reason')}; requeued {[r.get('reason') for r in case.requeues(job)]}")
    job = case.submit(case.program("short-c", SHORT))
    job = case.wait(job)
    holds &= av.outcome_ok(job)[0]
    observed.append(f"after freeing: {describe(job)}")
    began = time.monotonic()
    code = case.daemon.stop()
    took = time.monotonic() - began
    holds &= code == 0
    observed.append(f"SIGTERM: exit {code} in {took:.0f} s")
    return holds, "; ".join(observed)


def case_guest_panic(case):
    case.daemon.start(case.name, case.args.mem_gate_mb)
    job = case.wait(case.submit(case.program("panic", PANIC), timeout_run=60, run_as="root"))
    requeued = case.requeues(job)
    lane = case.lane_state()
    after = case.wait(case.submit(case.program("short", SHORT)))
    holds = (job.get("state") == "failed" and (job.get("failure") or {}).get("code") == "guest_lost"
             and not lane.get("quarantine") and av.outcome_ok(after)[0])
    return holds, (f"{describe(job)}; requeued {[r.get('reason') for r in requeued]}; quarantine "
                   f"{lane.get('quarantine')}; next job {describe(after)}")


def case_revert_corrupt(case):
    lane_file = case.work.read_lane_file(1)
    vm_dir = case.work.data / lane_file["vm_id"]
    relative = snapshot_disk(json.loads((vm_dir / "snapshots.json").read_text()), lane_file["clean_snapshot_id"])
    if not relative:
        raise av.Failure("the clean snapshot is not in the VM's snapshots.json")
    layer = vm_dir / relative
    layer.chmod(layer.stat().st_mode | 0o200)
    with open(layer, "r+b") as file:
        file.write(b"\0" * 65536)
    print(f"     overwrote the first 64 KiB of {relative} (the clean snapshot's layer)", flush=True)
    case.daemon.start(case.name, case.args.mem_gate_mb)
    first = case.submit(case.program("short-1", SHORT))
    second = case.submit(case.program("short-2", SHORT))
    first = case.wait(first)
    second_state = case.wait(second, until=lambda j: av.is_terminal(j) or j.get("waiting_for") == "lane_quarantined",
                             timeout=180)
    lane = case.lane_state()
    case.cli.run("auto", "cancel", second["id"], daemon=True, timeout=120)
    holds = (first.get("state") == "failed" and (first.get("failure") or {}).get("code") == "revert_failed"
             and (lane.get("quarantine") == "revert_failed") and second_state.get("waiting_for") == "lane_quarantined")
    return holds, (f"{describe(first)}; lane-1 quarantine {lane.get('quarantine')} ({lane.get('quarantine_detail')}); "
                   f"next job {second_state.get('state')} waiting_for {second_state.get('waiting_for')}")


RUNNERS = {"qemu-kill": case_qemu_kill, "daemon-kill": case_daemon_kill, "disk-full": case_disk_full_inner,
           "guest-panic": case_guest_panic, "revert-corrupt": case_revert_corrupt}


def run_case(args, name, factor, accel, data=None, data_root=None):
    case = Case(args, name, factor, accel, data, data_root)
    case.watch.start()
    print(f"== {name}: expected {EXPECTED[name]}", flush=True)
    started = time.monotonic()
    try:
        if name == "disk-full":
            case.setup(min_free_disk_gib=DISK_FLOOR_GIB, quota_gib=DISK_QUOTA_GIB)
        else:
            case.setup()
        holds, observed = RUNNERS[name](case)
    except av.Abort:
        raise
    except av.Failure as error:
        holds, observed = False, f"stopped: {error}"
    finally:
        stray = case.finish()
    if stray:
        holds, observed = False, observed + f"; unrecorded QEMU left: {stray}"
    print(f"{'ok  ' if holds else 'FAIL'} {name}: {observed} ({time.monotonic() - started:.0f} s)", flush=True)
    return holds, observed


def run_disk_full(args, argv, factor, accel):
    """disk-full on --quota-dir, or in a namespace with a tmpfs of its own."""
    folder = Path(args.work).resolve() / "cases" / "disk-full"
    if args.quota_dir:
        mount = args.quota_dir.resolve()
        if os.stat(mount).st_dev == os.stat(mount.parent).st_dev:
            raise av.Failure(f"--quota-dir {mount} is not a mount point")
        return run_case(args, "disk-full", factor, accel, data=mount / "data", data_root=mount)
    mount = folder / "quota"
    mount.mkdir(parents=True, exist_ok=True)
    result = folder / "out" / "result.json"
    result.unlink(missing_ok=True)
    command = quota_argv(Path(__file__).resolve(), argv, mount, args.quota_mib, sys.executable)
    print(f"     disk-full in a user+mount namespace, tmpfs of {args.quota_mib} MiB at {mount}", flush=True)
    done = subprocess.run(command, timeout=None)
    try:
        holds, observed = json.loads(result.read_text())
    except (OSError, ValueError):
        holds, observed = False, f"the namespaced run ended {done.returncode} without a result"
    if mount.is_dir() and not any(mount.iterdir()):
        mount.rmdir()
    return holds, observed


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = parser().parse_args(argv)
    work, cli, accel, factor = av.preamble(args, __file__, argv, "T7 faults")
    if args.quota_inner:
        holds, observed = run_case(args, "disk-full", factor, accel, data=args.quota_inner / "data")
        out = Path(args.work).resolve() / "cases" / "disk-full" / "out" / "result.json"
        out.write_text(json.dumps([holds, observed]))
        return 0 if holds else 1
    checks = av.Checks(work, f"T7 faults ({', '.join(args.case)}), TCG={accel == 'tcg'}")
    if args.dry_run:
        steps = [f"{name}: own data folder, base copy, auto init, policy t7 {POLICY}; expected: {EXPECTED[name]}"
                 for name in args.case]
        if "disk-full" in args.case and not args.quota_dir:
            steps.append("disk-full namespace: " + shlex.join(quota_argv(Path(__file__).resolve(), argv,
                         Path(args.work).resolve() / "cases/disk-full/quota", args.quota_mib, sys.executable)))
        code = av.dry_run(work, cli, checks, steps)
        av.cleanup(work, keep=args.keep, say=checks.note)
        return code
    av.enter_vm_slot(args.vm_slot, __file__, argv)
    rows = []
    try:
        for name in args.case:
            if name == "disk-full":
                holds, observed = run_disk_full(args, argv, factor, accel)
            else:
                holds, observed = run_case(args, name, factor, accel)
            rows.append((name, holds, observed))
            checks.check(holds, f"{name}: {observed}")
    except av.Failure as error:
        checks.check(False, f"stopped: {error}")
    checks.say("\n| Case | Expected | Observed | Held |\n|---|---|---|---|")
    for name, holds, observed in rows:
        checks.say(f"| {name} | {EXPECTED[name]} | {observed} | {'yes' if holds else 'no'} |")
    return checks.summary()


if __name__ == "__main__":
    sys.exit(main())
