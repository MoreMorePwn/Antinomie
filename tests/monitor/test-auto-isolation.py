#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""T6 (design 7.2): the revert proof, for each revert strategy.

For each strategy three jobs run in a row on one lane under `auto daemon`:
job 1 (a benign shell script, as root) drops /tmp/marker, appends a line to
an existing file on the guest disk (/etc/hosts, else /etc/hostname) and
creates /etc/antinomie-t6-new, syncs and reads them back (exit 0 only when
all three are there). Jobs 2 and 3 run a probe that exits 0 when none of the
three is visible and 40 + a bit mask otherwise (1 the marker, 2 the changed
file, 4 the new file). Each strategy has its own token, so no strategy can
see another's leftovers by accident.

  snapshot_disk  the lane as `auto init` makes it (Disk snapshot auto-clean,
                 restore and cold boot): the default.
  snapshot_full  the lane VM is reverted to auto-clean, a Disk+memory snapshot
                 auto-clean-full is taken headless with the daemon's flags
                 (`snapshot create --mode full`), and the lane file's clean
                 snapshot is pointed at it while the daemon is stopped: `auto
                 init` takes Disk snapshots only, so this is the harness's own
                 setup (see the task record). The lane file is put back after.
  reset          a policy with `vm.revert = "reset"` is checked with
                 `config validate --policy` first. The engine refuses `Reset`
                 on a VM with snapshots and every auto lane has its clean
                 snapshot, so on the current code this is expected to be
                 refused there; the strategy is then reported BLOCKED with the
                 validator's words and no job is run.

    test-auto-isolation.py --work DIR --base BASE [--revert snapshot_disk,...]

Exit 0 when every strategy proves the revert, 2 when the only problems are
BLOCKED strategies, 1 otherwise.
"""
import importlib.util
import json
from pathlib import Path
import secrets
import sys
import time

spec = importlib.util.spec_from_file_location("auto_vm", Path(__file__).resolve().with_name("auto_vm.py"))
av = importlib.util.module_from_spec(spec)
sys.modules["auto_vm"] = av
spec.loader.exec_module(av)

STRATEGIES = ("snapshot_disk", "snapshot_full", "reset")
FULL_SNAPSHOT = "auto-clean-full"
JOB_TIMEOUT_S = 600
SEED = r"""
# T6 seed (benign): a marker in /tmp, one changed and one new file on the disk.
T=TOKEN
echo "$T" > /tmp/marker || exit 51
F=/etc/hosts
[ -f "$F" ] || F=/etc/hostname
echo "# $T" >> "$F" || exit 52
echo "$T" > /etc/antinomie-t6-new || exit 53
sync
grep -q "$T" /tmp/marker || exit 54
grep -q "$T" "$F" || exit 55
grep -q "$T" /etc/antinomie-t6-new || exit 56
echo "t6 seeded $T in /tmp/marker, $F and /etc/antinomie-t6-new"
"""
PROBE = r"""
# T6 probe (benign): exit 0 when nothing of the seed is visible.
T=TOKEN
c=0
[ -e /tmp/marker ] && c=$((c + 1))
if grep -qs "$T" /etc/hosts || grep -qs "$T" /etc/hostname; then c=$((c + 2)); fi
[ -e /etc/antinomie-t6-new ] && c=$((c + 4))
echo "t6 probe $T: $c"
[ "$c" -eq 0 ] && exit 0
exit $((40 + c))
"""
PROBE_BITS = ((1, "/tmp/marker"), (2, "the changed file"), (4, "/etc/antinomie-t6-new"))


def probe_seen(code):
    """What a probe's exit code says it saw: [] for nothing, None when the code
    is not one the probe gives."""
    if code == 0:
        return []
    if isinstance(code, int) and 41 <= code <= 47:
        return [name for bit, name in PROBE_BITS if (code - 40) & bit]
    return None


def strategies(text):
    chosen = [s.strip() for s in text.split(",") if s.strip()]
    unknown = [s for s in chosen if s not in STRATEGIES]
    if unknown or not chosen:
        raise SystemExit(f"--revert takes {', '.join(STRATEGIES)}; got {text!r}")
    return chosen


def policy_name(mode):
    return "t6-" + mode.replace("_", "-")


def policy_changes(mode):
    return {("sample", "accept_types"): '["elf", "sh"]', ("run", "allow_root"): "true",
            ("vm", "revert"): f'"{mode}"',
            ("vm", "revert_to"): f'"{FULL_SNAPSHOT if mode == "snapshot_full" else "auto-clean"}"'}


def parser():
    p = av.common_parser(__doc__, prog="test-auto-isolation.py")
    p.add_argument("--revert", type=strategies, default=list(STRATEGIES),
                   help=f"strategies, in order [{','.join(STRATEGIES)}]")
    return p


def plan(args):
    steps = ["base install; auto init (lane 1); service.toml lanes = 1"]
    for mode in args.revert:
        if mode == "snapshot_full":
            steps.append(f"daemon stopped: snapshot restore auto-1 auto-clean --yes; snapshot create auto-1 "
                         f"{FULL_SNAPSHOT} --mode full; point service/lanes/lane-1.json at it")
        steps.append(f"policies/{policy_name(mode)}.toml: {policy_changes(mode)}; config validate --policy")
        steps.append(f"{mode}: auto daemon; seed (as root), probe, probe; daemon SIGTERM")
    steps.append("delete the VM data")
    return steps


def snapshot_id(cli, vm, name):
    items = cli.ok("snapshot", "list", vm, engine=True, timeout=600).get("items", [])
    return next((item.get("id") for item in items if item.get("name") == name), None)


def prepare_full(cli, work, args, vm, factor, checks):
    timeout = int(1800 * factor)
    av.mem_gate(args.mem_gate_mb, 3600 * factor, "snapshot restore")
    cli.ok("snapshot", "restore", vm, "auto-clean", "--yes", engine=True, timeout=timeout)
    av.mem_gate(args.mem_gate_mb, 3600 * factor, "snapshot create --mode full")
    cli.ok("snapshot", "create", vm, FULL_SNAPSHOT, "--mode", "full", engine=True, timeout=timeout)
    full = snapshot_id(cli, vm, FULL_SNAPSHOT)
    lane = work.read_lane_file(1)
    if not full or not lane:
        raise av.Failure(f"no {FULL_SNAPSHOT} snapshot ({full}) or no lane file")
    original = dict(lane)
    lane["clean_snapshot_id"] = full
    work.write_lane_file(1, lane)
    checks.note(f"snapshot_full: lane-1 points at the Full snapshot {full} (was {original['clean_snapshot_id']})")
    return original


def run_strategy(cli, work, args, factor, checks, mode, daemon, watch):
    """'pass', 'fail' or 'blocked'."""
    name = policy_name(mode)
    av.edit_policy(work, name, policy_changes(mode))
    code, parsed, err = cli.run("config", "validate", "--policy", name, timeout=300)
    if code != 0:
        words = json.dumps(parsed)[:600] if parsed else err.strip()[-600:]
        checks.say(f"BLOCKED {mode}: config validate --policy {name} exit {code}: {words}")
        work.policy(name).unlink()
        return "blocked"
    token = f"t6-{mode}-{secrets.token_hex(4)}"
    seed = av.write_guest_script(work.samples / f"seed-{mode}.sh", SEED.replace("TOKEN", token))
    probe = av.write_guest_script(work.samples / f"probe-{mode}.sh", PROBE.replace("TOKEN", token))
    daemon.start(mode, args.mem_gate_mb)
    ok = True
    try:
        jobs = []
        for step, program in enumerate((seed, probe, probe), start=1):
            job = av.submit(cli, program, policy=name, timeout_run=60, run_as="root", name=f"{mode}-{step}")
            job = av.wait_job(cli, job["id"], JOB_TIMEOUT_S * factor, watch=watch, daemon=daemon)
            jobs.append(job)
            run = job.get("run") or {}
            fine, why = av.outcome_ok(job)
            ok &= checks.check(fine and (job.get("vm") or {}).get("revert") == mode,
                               f"{mode} job {step} ({job['id'][-8:]}) ended {why}, vm.revert {(job.get('vm') or {}).get('revert')}")
            if step == 1:
                changed = ((job.get("assessment") or {}).get("counts") or {}).get("files_changed")
                ok &= checks.check(run.get("exit") == 0,
                                   f"{mode} job 1 seeded the marker and both files (exit {run.get('exit')}; "
                                   f"{changed} file(s) changed in the recording)")
            else:
                seen = probe_seen(run.get("exit"))
                ok &= checks.check(seen == [], f"{mode} job {step} sees nothing of job 1"
                                   + ("" if seen == [] else f": exit {run.get('exit')}, saw {seen}"))
        for step, job in enumerate(jobs, start=1):
            durations = av.stage_durations(av.events_of(cli, job["id"]))
            checks.note(f"{mode} job {step}: provision {durations.get('provision', 0) / 1000:.1f} s, "
                        f"run {durations.get('run', 0) / 1000:.1f} s")
    finally:
        code = daemon.stop()
        checks.note(f"{mode}: daemon stopped with {code}")
    return "pass" if ok else "fail"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = parser().parse_args(argv)
    work, cli, accel, factor = av.preamble(args, __file__, argv, "T6 isolation")
    checks = av.Checks(work, f"T6 revert proof ({', '.join(args.revert)}), TCG={accel == 'tcg'}")
    base_copy = work.copy_base(args.base)
    if args.dry_run:
        code = av.dry_run(work, cli, checks, plan(args))
        av.cleanup(work, keep=args.keep, say=checks.note)
        return code
    av.enter_vm_slot(args.vm_slot, __file__, argv)
    daemon = av.Daemon(cli, factor)
    watch = av.MemWatch(work, args.mem_floor_mb, daemon)
    watch.start()
    results = {}
    began = time.monotonic()
    try:
        av.install_base(cli, base_copy)
        lane = av.init_lane(cli, args, 1, factor=factor)
        (work.data / "service.toml").write_text(av.service_toml(lanes=1, require_kvm=accel == "kvm"))
        for mode in args.revert:
            original = None
            try:
                if mode == "snapshot_full":
                    original = prepare_full(cli, work, args, lane["vm_name"], factor, checks)
                results[mode] = run_strategy(cli, work, args, factor, checks, mode, daemon, watch)
            except av.Abort:
                raise
            except av.Failure as error:
                checks.check(False, f"{mode} stopped: {error}")
                results[mode] = "fail"
                if daemon.alive():
                    daemon.stop()
            finally:
                if original:
                    work.write_lane_file(1, original)
    except av.Failure as error:
        checks.check(False, f"stopped: {error}")
    finally:
        watch.stop()
        checks.note(f"elapsed {time.monotonic() - began:.0f} s; minimum MemAvailable {watch.minimum} MB")
        av.cleanup(work, [daemon], args.keep, say=checks.note)
    checks.note("strategies: " + ", ".join(f"{mode} {results.get(mode, 'not run')}" for mode in args.revert))
    code = checks.summary()
    if code == 0 and "blocked" in results.values():
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
