#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""The Auto mode VM tiers (test-auto-smoke/isolation/faults/soak.py and
auto_vm.py) without a VM: argument handling, the preset and service.toml
edits, the job, event and report checks, the recorded-PID rule, the probe
codes, the quota namespace command, the soak's table and its resume files.

Needs Python 3.11 or later (`tomllib`): run it with /usr/bin/python3 where
the default python3 is older, e.g. `/usr/bin/python3 -I tests/monitor/test-auto-harness.py`."""
import sys

if sys.version_info < (3, 11):
    sys.exit(f"test-auto-harness.py needs Python 3.11 or later (tomllib); this is {sys.version.split()[0]}: "
             "run it with /usr/bin/python3")

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import types
import unittest
import unittest.mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


av = load("auto_vm", "auto_vm.py")
smoke = load("auto_smoke", "test-auto-smoke.py")
isolation = load("auto_isolation", "test-auto-isolation.py")
faults = load("auto_faults", "test-auto-faults.py")
soak = load("auto_soak", "test-auto-soak.py")
PRESET_EXAMPLE = ROOT / "packaging/presets/standard.toml.example"


def finished_job(**changes):
    """A finished job in the shape `auto status JOB` gives (trimmed)."""
    job = {
        "id": "j_01TEST", "state": "succeeded", "stage": None, "waiting_for": None, "attempt": 1,
        "created_ms": 1000, "started_ms": 1010, "finished_ms": 5000, "lane": "lane-1",
        "sample": {"sha256": "a" * 64, "type": "elf"},
        "vm": {"id": "auto_1_x", "name": "auto-1", "base_identity": "b" * 64, "revert": "snapshot_disk"},
        "program": {"id": "r1", "end_reason": "exited", "exit": 0},
        "recording": {"run_id": "r1", "phase": "complete", "directory": "/data/auto_1_x/runs/r1"},
        "assessment": {"assessment": "observed_only", "label": "clean_observed", "basis": "Only low-tier ...",
                       "counts": {"processes": 3}},
        "artifacts": [{"kind": "report.html", "size": 10, "sha256": "c" * 64},
                      {"kind": "report.json", "size": 20, "sha256": "d" * 64}],
        "warnings": [], "failure": None,
        "host_work": [{"name": n, "state": "done", "expected_s": 1, "limit_s": 30, "note": None}
                      for n in ("triage", "static:metadata", "detection", "assess", "report")],
    }
    job.update(changes)
    return job


def events(*stages, gap=False):
    out = [{"seq": 1, "type": "run.created", "data": {}}]
    for stage in stages:
        out.append({"type": "run.stage", "data": {"stage": stage, "status": "started"}})
        out.append({"type": "run.stage", "data": {"stage": stage, "status": "finished", "duration_ms": 100}})
    out.append({"type": "run.finished", "data": {"outcome": "succeeded"}})
    for number, event in enumerate(out, start=1):
        event["seq"] = number + (1 if gap and number > 3 else 0)
    return out


class ArgumentTests(unittest.TestCase):
    def test_guest_ram_is_512_to_2048(self):
        parser = av.common_parser("x")
        base = ["--work", "w", "--base", "b"]
        self.assertEqual(parser.parse_args(base).ram_mib, 512)
        self.assertEqual(parser.parse_args(base + ["--ram-mib", "2048"]).ram_mib, 2048)
        for bad in ("256", "4096"):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(base + ["--ram-mib", bad])

    def test_accel_and_time_factor(self):
        self.assertEqual(av.resolve_accel("auto", False), "tcg")
        self.assertEqual(av.resolve_accel("auto", True), "kvm")
        with self.assertRaises(av.Failure):
            av.resolve_accel("kvm", False)
        self.assertEqual(av.time_factor(None, "kvm", {}), 1.0)
        self.assertEqual(av.time_factor(None, "tcg", {}), av.TCG_FACTOR)
        self.assertEqual(av.time_factor(None, "tcg", {av.FACTOR_ENV: "7"}), 7.0)
        self.assertEqual(av.time_factor(2.5, "tcg", {av.FACTOR_ENV: "7"}), 2.5)
        with self.assertRaises(av.Failure):
            av.time_factor(0.5, "kvm", {})

    def test_the_slot_wraps_the_script_once(self):
        self.assertIsNone(av.slot_argv("", "s.py", ["--work", "w"], "/usr/bin/python3", {}))
        self.assertIsNone(av.slot_argv("flock h vm-slot.sh", "s.py", [], "py", {av.SLOT_HELD_ENV: "1"}))
        command = av.slot_argv("flock /l/heavy.lock /t/vm-slot.sh", "s.py", ["--work", "w x"], "/usr/bin/python3", {})
        self.assertEqual(command[:3], ["flock", "/l/heavy.lock", "/t/vm-slot.sh"])
        self.assertEqual(command[3:6], ["env", f"{av.SLOT_HELD_ENV}=1", "/usr/bin/python3"])
        self.assertEqual(command[6], "-I")
        self.assertTrue(Path(command[7]).is_absolute())
        self.assertEqual(command[-2:], ["--work", "w x"])

    def test_isolation_strategies_and_fault_cases(self):
        self.assertEqual(isolation.strategies("snapshot_full, snapshot_disk"), ["snapshot_full", "snapshot_disk"])
        self.assertEqual(faults.cases("disk-full"), ["disk-full"])
        for parse, text in ((isolation.strategies, "clone"), (isolation.strategies, "reset"), (faults.cases, "oom")):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                parse(text)

    def test_soak_durations(self):
        self.assertEqual(soak.duration("24h"), 86400)
        self.assertEqual(soak.duration("90m"), 5400)
        self.assertEqual(soak.duration("3600"), 3600)
        with self.assertRaises(Exception):
            soak.duration("soon")
        args = soak.parser().parse_args(["--work", "w", "--base", "b", "--max-mem-floor-mb", "3000"])
        self.assertEqual(args.mem_floor_mb, 3000)
        self.assertEqual(soak.parser().parse_args(["--work", "w", "--base", "b"]).mem_floor_mb, 2500)


class TomlTests(unittest.TestCase):
    def test_a_key_is_replaced_in_its_own_section_only(self):
        text = "[a]\nx = 1  # one\ny = 2\n\n[b]\nx = 5\n"
        out = av.set_toml_key(text, "a", "x", "9")
        parsed = tomllib.loads(out)
        self.assertEqual((parsed["a"]["x"], parsed["a"]["y"], parsed["b"]["x"]), (9, 2, 5))
        self.assertIn("# one", out)

    def test_a_missing_key_or_section_is_added(self):
        parsed = tomllib.loads(av.set_toml_key(av.set_toml_key("[a]\nx = 1\n\n[b]\ny = 1\n", "a", "z", '"q"'),
                                               "c", "k", "true"))
        self.assertEqual(parsed, {"a": {"x": 1, "z": "q"}, "b": {"y": 1}, "c": {"k": True}})

    def test_the_tier_settings_parse_from_the_shipped_files(self):
        service = av.service_toml(lanes=1, require_kvm=False)
        for mode in isolation.STRATEGIES:
            with self.subTest(mode=mode):
                edited = service
                for (section, key), value in isolation.lane_changes(mode).items():
                    edited = av.set_toml_key(edited, section, key, value)
                parsed = tomllib.loads(edited)
                self.assertEqual(parsed["lanes"]["revert"], mode)
                self.assertEqual(parsed["daemon"]["lanes"], 1)
        standard = tomllib.loads(PRESET_EXAMPLE.read_text())
        self.assertEqual(standard["accepts"]["types"], ["elf", "sh"])
        self.assertEqual(standard["program"]["run_time_s"], 300)
        edited = PRESET_EXAMPLE.read_text()
        for (section, key), value in faults.PRESET.items():
            edited = av.set_toml_key(edited, section, key, value)
        self.assertEqual(tomllib.loads(edited)["retry"]["backoff_s"], [10, 10])

    def test_a_preset_file_is_standard_with_the_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            work = types.SimpleNamespace(preset=lambda name: Path(folder) / "presets" / f"{name}.toml")
            path = av.edit_preset(work, "t7", faults.PRESET)
            self.assertEqual(tomllib.loads(path.read_text()),
                             {"title": "t7", "retry": {"backoff_s": [10, 10]}})

    def test_service_toml(self):
        parsed = tomllib.loads(av.service_toml(lanes=2, require_kvm=False, min_free_disk_gib=1,
                                               retention={"recordings_days": 1, "max_recordings_gib": 2}))
        self.assertEqual(parsed, {"daemon": {"lanes": 2}, "resources": {"require_kvm": False, "min_free_disk_gib": 1},
                                  "retention": {"recordings_days": 1, "max_recordings_gib": 2}})
        self.assertEqual(tomllib.loads(av.service_toml(socket=Path("/tmp/x/antinomie.sock")))["daemon"]["socket"],
                         "/tmp/x/antinomie.sock")

    def test_a_long_data_path_gets_a_short_private_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            short = av.Work(Path(tmp) / "w").prepare()
            self.assertIsNone(short.socket_override())
            self.assertEqual(short.socket_path(), short.data / "run" / "antinomie.sock")
            deep = av.Work(Path(tmp) / ("d" * 120)).prepare()
            socket = deep.socket_override()
            try:
                self.assertLessEqual(len(os.fsencode(str(socket))), av.SOCKET_PATH_MAX)
                self.assertEqual(socket, deep.socket_override())
                self.assertEqual(deep.socket_path(), socket)
                self.assertEqual(os.stat(socket.parent).st_mode & 0o777, 0o700)
                av.cleanup(deep, say=lambda _: None)
                self.assertFalse(socket.parent.exists())
            finally:
                if socket.parent.is_dir():
                    socket.parent.rmdir()


class JobCheckTests(unittest.TestCase):
    def test_a_good_job_passes_every_check(self):
        failed = [m for ok, m in av.job_checks(finished_job(), vm_name="auto-1", base_identity="b" * 64) if not ok]
        self.assertEqual(failed, [])

    def test_partial_counts_only_for_missing_host_tools(self):
        host = finished_job(state="partial", warnings=[{"code": "static_check_incomplete"},
                                                       {"code": "detection_skipped"}])
        self.assertTrue(av.outcome_ok(host)[0])
        self.assertFalse(av.outcome_ok(host, strict=True)[0])
        other = finished_job(state="partial", warnings=[{"code": "capture_incomplete"}])
        self.assertEqual(av.outcome_ok(other), (False, "partial with capture_incomplete"))
        self.assertFalse(av.outcome_ok(finished_job(state="failed", failure={"code": "guest_lost"}))[0])

    def test_wrong_details_fail_their_check(self):
        cases = {
            "exit": finished_job(program={"id": "r1", "end_reason": "exited", "exit": 3}),
            "revert": finished_job(vm={"id": "auto_1_x", "name": "auto-1", "revert": "reset"}),
            "phase": finished_job(recording={"run_id": "r1", "phase": "finalizing"}),
            "label": finished_job(assessment={"label": "maybe", "basis": "", "counts": {}}),
            "artifact": finished_job(artifacts=[]),
            "host": finished_job(host_work=[{"name": "triage", "state": "failed", "expected_s": 1, "limit_s": 2}]),
        }
        for name, job in cases.items():
            with self.subTest(name=name):
                self.assertTrue(any(not ok for ok, _ in av.job_checks(job)))

    def test_host_work_limits(self):
        job = finished_job()
        job["host_work"].append({"name": "static:capabilities", "state": "failed", "note": "not available",
                                 "expected_s": 91, "limit_s": 182})
        self.assertEqual(av.host_work_problems(job), [])
        job["host_work"].append({"name": "static:x", "state": "done", "expected_s": 10, "limit_s": 5})
        self.assertEqual(len(av.host_work_problems(job)), 1)

    def test_events(self):
        good = events(*av.STAGES)
        self.assertEqual(av.event_problems(good), [])
        self.assertEqual(av.stage_durations(good)["run"], 100)
        self.assertTrue(any("gap" in p for p in av.event_problems(events(*av.STAGES, gap=True))))
        self.assertTrue(any("report" in p for p in av.event_problems(events(*av.STAGES[:7]))))
        swapped = list(av.STAGES)
        swapped[1], swapped[2] = swapped[2], swapped[1]
        self.assertTrue(any("order" in p for p in av.event_problems(events(*swapped))))

    def test_report_json(self):
        job = finished_job()
        report = {"schema": "antinomie-triage-report", "schema_version": 2,
                  "run": {"run_id": "r1", "vm_id": "auto_1_x"}, "sample": {"sha256": "a" * 64},
                  "summary": {"assessment": "observed_only"},
                  "processes": {"columns": ["Process"], "rows": [["demo (1 \u00b7 1)"]], "omitted": 0,
                                "indicator_columns": [], "data": [{"id": "proc-1", "pid": 1}]}}
        self.assertTrue(all(ok for ok, _ in av.report_json_checks(report, job)))
        self.assertFalse(all(ok for ok, _ in av.report_json_checks(dict(report, processes=[{"pid": 1}]), job)))
        self.assertFalse(all(ok for ok, _ in av.report_json_checks(
            dict(report, processes=dict(report["processes"], rows=[])), job)))
        report["run"]["run_id"] = "other"
        self.assertFalse(all(ok for ok, _ in av.report_json_checks(report, job)))

    def test_envelopes(self):
        self.assertEqual(av.unwrap({"ok": True, "result": {"a": 1}}), {"a": 1})
        self.assertIsNone(av.unwrap({"ok": False, "error": {"code": "x"}}))
        self.assertEqual(av.job_of({"run": {"id": "r"}, "replayed": False}), {"id": "r"})
        self.assertEqual(av.job_of({"id": "j", "job": None}), {"id": "j", "job": None})


class ProcessTests(unittest.TestCase):
    def test_only_a_recorded_process_with_the_same_start_is_alive(self):
        me = os.getpid()
        record = {"pid": me, "start_ticks": av.start_ticks(me), "marker": "python"}
        self.assertTrue(av.recorded_alive(record))
        self.assertFalse(av.recorded_alive(dict(record, start_ticks=record["start_ticks"] + 1)))
        self.assertFalse(av.recorded_alive(dict(record, marker="auto_1_not_this")))
        self.assertFalse(av.recorded_alive({"pid": 2 ** 22 + 7, "marker": ""}))
        self.assertFalse(av.recorded_alive(None))
        with unittest.mock.patch.object(av.os, "kill") as kill:
            self.assertFalse(av.kill_recorded(dict(record, start_ticks=record["start_ticks"] + 1)))
            kill.assert_not_called()

    def test_safe_rmtree_stays_below_its_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "work"
            (root / "data" / "x").mkdir(parents=True)
            outside = Path(tmp) / "outside"
            (outside / "keep").mkdir(parents=True)
            (root / "link").symlink_to(outside)
            for bad in (root, Path(tmp), root / "link" / "keep"):
                with self.subTest(bad=bad), self.assertRaises(av.Failure):
                    av.safe_rmtree(bad, root)
            av.safe_rmtree(root / "link", root)
            self.assertTrue((outside / "keep").is_dir())
            av.safe_rmtree(root / "data", root)
            self.assertFalse((root / "data").exists())

    def test_the_cli_surface_is_checked_against_help(self):
        self.assertEqual(av.missing_flags("  --lane <N>\n  --ram-mib <N>  x\n", ["--lane", "--ram-mib", "--cpus"]),
                         ["--cpus"])
        with tempfile.TemporaryDirectory() as tmp:
            work = av.Work(Path(tmp) / "w").prepare()
            fake = Path(tmp) / "fake-cli"
            flags = sorted({flag for group in av.CLI_SURFACE.values() for flag in group})
            fake.write_text("#!/bin/sh\n[ \"$1\" = --version ] && { echo 'antinomie-cli 0.9.0'; exit 0; }\n"
                            "echo 'Usage: antinomie-cli'\n" + "".join(f"echo '  {f} <X>'\n" for f in flags))
            fake.chmod(0o755)
            results = av.check_cli_surface(av.Cli(fake, work, "tcg"))
            self.assertEqual([m for ok, m in results if not ok], [])
            fake.write_text("#!/bin/sh\necho 'Usage: antinomie-cli'\n")
            results = av.check_cli_surface(av.Cli(fake, work, "tcg"))
            self.assertTrue(any("lacks --lane" in m for ok, m in results if not ok))
            missing = av.check_cli_surface(av.Cli(Path(tmp) / "none", work, "tcg"))
            self.assertFalse(missing[0][0])

    def test_a_random_guest_password_goes_to_auto_init_on_stdin_only(self):
        parser = av.common_parser("x")
        base = ["--work", "w", "--base", "b"]
        self.assertFalse(parser.parse_args(base).random_guest_password)
        args = parser.parse_args(base + ["--random-guest-password", "--mem-gate-mb", "0"])
        self.assertTrue(args.random_guest_password)
        password = av.guest_password()
        self.assertEqual(password, av.guest_password(), "one password per run")
        self.assertTrue(8 <= len(password.encode()) <= 128)
        self.assertFalse(set(password) & {"\0", "\r", "\n"})
        with tempfile.TemporaryDirectory() as tmp:
            work = av.Work(tmp).prepare()
            fake = Path(tmp) / "cli"
            # The fake CLI says what it read on stdin, as a careless one might.
            fake.write_text("#!/bin/sh\nread line\necho \"{\\\"lane\\\": \\\"$line\\\"}\"\n"
                            "echo \"read $line\" >&2\n")
            fake.chmod(0o755)
            cli = av.Cli(fake, work, "kvm")
            with unittest.mock.patch.object(av, "mem_gate"):
                lane = av.init_lane(cli, args, 1)
            # The fake echoed exactly the password it read; the harness
            # redacted it before it parsed or logged the reply.
            self.assertEqual(lane, "<redacted>", "the password went to stdin")
            log = (work.out / "cli.log").read_text()
            self.assertIn("--password-stdin", log)
            self.assertNotIn(password, log)
            self.assertIn("<redacted>", log)
            leftovers = [p for p in Path(tmp).rglob("*") if p.is_file() and password in p.read_text(errors="replace")]
            self.assertEqual(leftovers, [])

    def test_engine_flags_go_only_to_engine_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli = av.Cli("/bin/cli", av.Work(tmp).prepare(), "tcg", tcg_multiplier=12)
            self.assertIn("--tcg", cli.argv(["auto", "init"], engine=True))
            self.assertIn("12", cli.argv(["auto", "init"], engine=True))
            self.assertNotIn("--tcg", cli.argv(["auto", "status"]))
            self.assertIn("--daemon", cli.argv(["auto", "status"], daemon=True))
            self.assertEqual(cli.argv(["x"])[1:3], ["--data-dir", str(Path(tmp).resolve() / "data")])

    def test_the_private_environment(self):
        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict(
                os.environ, {"WAYLAND_DISPLAY": "w", av.SLOT_HELD_ENV: "1"}):
            work = av.Work(tmp).prepare()
            env = work.env()
            for var in ("HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
                self.assertTrue(env[var].startswith(str(work.home)), var)
            self.assertNotIn("WAYLAND_DISPLAY", env)
            self.assertNotIn(av.SLOT_HELD_ENV, env)
            self.assertEqual(work.lane_dir(1), work.data)
            self.assertEqual(work.lane_dir(3), work.data / "lanes" / "3")

    def test_a_lane_file_is_rewritten_whole(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = av.Work(tmp).prepare()
            work.lane_file(1).parent.mkdir(parents=True)
            work.write_lane_file(1, {"version": 1, "clean_snapshot_id": "s1"})
            work.write_lane_file(1, dict(work.read_lane_file(1), clean_snapshot_id="s2"))
            self.assertEqual(work.read_lane_file(1), {"version": 1, "clean_snapshot_id": "s2"})
            self.assertEqual([p.name for p in work.lane_file(1).parent.iterdir()], ["lane-1.json"])


class IsolationAndFaultTests(unittest.TestCase):
    def test_probe_codes(self):
        self.assertEqual(isolation.probe_seen(0), [])
        self.assertEqual(isolation.probe_seen(41), ["/tmp/marker"])
        self.assertEqual(isolation.probe_seen(47), ["/tmp/marker", "the changed file", "/etc/antinomie-t6-new"])
        for code in (1, 40, 48, None, 54):
            self.assertIsNone(isolation.probe_seen(code))

    def test_the_guest_scripts_carry_their_token(self):
        for script in (isolation.SEED, isolation.PROBE):
            self.assertIn("T=TOKEN", script)
            self.assertNotIn("rm -", script)
        self.assertIn("/proc/sysrq-trigger", faults.PANIC)
        self.assertIn("150", faults.LONGER)

    def test_without_option(self):
        self.assertEqual(faults.without_option(["--case", "a", "--work", "w", "--case=b", "--x"], "--case"),
                         ["--work", "w", "--x"])

    def test_the_quota_namespace_command(self):
        command = faults.quota_argv(Path("/r/test-auto-faults.py"), ["--work", "/w", "--case", "qemu-kill,disk-full"],
                                    Path("/w/cases/disk-full/quota"), 2560, "/usr/bin/python3")
        self.assertEqual(command[:6], ["unshare", "--user", "--map-current-user", "--mount", "--keep-caps", "sh"])
        shell = command[-1]
        self.assertTrue(shell.startswith("mount -t tmpfs -o size=2560m,mode=0700 antinomie-quota /w/cases/disk-full/quota && "))
        self.assertIn("exec setpriv --inh-caps=-all --ambient-caps=-all /usr/bin/python3 -I /r/test-auto-faults.py", shell)
        self.assertEqual(shell.count("--case"), 1)
        self.assertTrue(shell.endswith("--case disk-full --quota-inner /w/cases/disk-full/quota"))

    def test_the_clean_snapshot_layer_is_found_in_the_manifest(self):
        manifest = {"nodes": [{"checkpoint": {"id": "a"}, "disk": "snapshots/a.qcow2"},
                              {"checkpoint": {"id": "b"}, "disk": "snapshots/b.qcow2"}]}
        self.assertEqual(faults.snapshot_disk(manifest, "b"), "snapshots/b.qcow2")
        self.assertIsNone(faults.snapshot_disk(manifest, "c"))

    def test_fill_stops_at_what_it_should_leave(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "filler"

            def free(_folder):
                return 10 * av.MIB - (path.stat().st_size if path.exists() else 0)

            self.assertEqual(faults.fill(path, 4 * av.MIB, chunk=av.MIB, free=free), 6 * av.MIB)
            self.assertEqual(path.stat().st_size, 6 * av.MIB)
            self.assertEqual(faults.fill(path, 4 * av.MIB, chunk=av.MIB, free=free), 0)


class SoakTests(unittest.TestCase):
    def test_statistics(self):
        self.assertEqual(soak.p95([5, 1, 3, 2, 4]), 5)
        self.assertEqual(soak.p95(list(range(1, 101))), 95)
        self.assertIsNone(soak.p95([None]))
        self.assertAlmostEqual(soak.slope([1, 2, 3], [2, 4, 6]), 2.0)
        self.assertIsNone(soak.slope([1], [1]))
        self.assertIsNone(soak.slope([2, 2], [1, 3]))

    def samples(self):
        return [{"jobs": n, "fds": 40 + (n > 20), "rss_mib": 80.0 + n / 10, "service_mib": n * 0.5,
                 "snap_nodes": 2, "runs": min(n, 30)} for n in range(0, 41)]

    def test_growth_rows_start_after_the_warmup(self):
        rows = {row[0]: row for row in soak.growth_rows(self.samples(), 10)}
        self.assertEqual(rows["fds"][1:4], (40, 41, 1))
        self.assertAlmostEqual(rows["service_mib"][4], 50.0)
        self.assertEqual(rows["snap_nodes"][3], 0)
        self.assertEqual(rows["gc_recordings"][1:], (None,) * 5)

    def test_the_table_and_the_flat_line(self):
        jobs = [{"state": "succeeded" if n % 3 else "partial", "host_tools_only": True,
                 "stages": {"run": 1000 + n, "provision": 500}} for n in range(20)]
        state = {"elapsed_s": 7200, "phase": "done"}
        text = soak.table(self.samples(), jobs, 10)
        self.assertIn("| fds | 40 | 41 | 1 |", text)
        self.assertIn("| run |", text)
        line = soak.flat_line(state, self.samples(), jobs, 10)
        self.assertTrue(line.startswith("soak: 20 jobs in 2.0 h (partial 7, succeeded 13; "))
        self.assertIn("not succeeded/partial 0", line)
        self.assertIn("fds 40->41", line)
        self.assertNotIn("pass", line.lower())
        self.assertNotIn("fail", line.lower())
        self.assertEqual("\n" in line, False)

    def test_the_state_survives_a_cut_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = soak.Soak(av.Work(tmp).prepare())
            files.save({"phase": "running", "jobs": 2})
            self.assertEqual(files.state()["jobs"], 2)
            files.append(files.jobs_path, {"n": 1})
            with open(files.jobs_path, "a") as cut:
                cut.write('{"n": 2, "st')
            self.assertEqual(files.read(files.jobs_path), [{"n": 1}])

    def test_report_and_resume_refusals_start_nothing(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as out:
            common = ["--work", str(Path(tmp) / "w"), "--base", tmp, "--min-free-gb", "0", "--accel", "tcg"]
            self.assertEqual(soak.main(common + ["--report"]), 3)
            self.assertEqual(soak.main(common + ["--resume"]), 3)
            soak.Soak(av.Work(Path(tmp) / "w")).save({"phase": "stopped", "jobs": 4, "elapsed_s": 60})
            self.assertEqual(soak.main(common), 3)
            self.assertEqual(soak.main(common + ["--report"]), 0)
        self.assertIn("--resume", out.getvalue())


class SmokeTests(unittest.TestCase):
    def test_the_plan_names_each_lane(self):
        args = smoke.parser().parse_args(["--work", "w", "--base", "b", "--lanes", "2"])
        steps = smoke.plan(args, Path("demo-recon"), Path("base"))
        self.assertTrue(any("--lane 2" in s for s in steps))
        self.assertTrue(any("2 x antinomie-cli auto submit demo-recon" in s for s in steps))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            smoke.parser().parse_args(["--work", "w", "--base", "b", "--lanes", "3"])


if __name__ == "__main__":
    unittest.main()
