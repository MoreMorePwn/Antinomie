#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""scripts/vm-regress.py: tier choice, argument parsing and the check plan, without a VM."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/vm-regress.py"
spec = importlib.util.spec_from_file_location("vm_regress", SCRIPT)
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class TierTests(unittest.TestCase):
    def tier(self, *paths, revision=()):
        return vm.choose_tier(paths, revision)[0]

    def test_ordinary_changes_are_quick(self):
        self.assertEqual(self.tier("docs/implementation.md", "src/antinomie/monitor/crates/monitor-ui/src/lib.rs"),
                         "quick")
        self.assertEqual(self.tier(), "quick")

    def test_contract_paths_are_full(self):
        for path in ("src/antinomie/core/6.12/0051-x.patch", "src/antinomie/patches/series",
                     "src/antinomie/transport/ring.c", "src/antinomie/monitor/protocol/control.h",
                     "src/antinomie/monitor/protocol/native-syscalls.json"):
            with self.subTest(path=path):
                tier, reasons = vm.choose_tier(["README.md", path])
                self.assertEqual(tier, "full")
                self.assertEqual(len(reasons), 1)
                self.assertIn(path, reasons[0])

    def test_lookalike_prefixes_are_quick(self):
        self.assertEqual(self.tier("src/antinomie/core-notes.md", "src/antinomie/monitor/protocol-tools/a.rs",
                                   "docs/src/antinomie/core/x"), "quick")

    def test_revision_change_is_full(self):
        tier, reasons = vm.choose_tier(["src/antinomie/monitor/crates/monitor-core/src/control.rs"],
                                       ["src/antinomie/monitor/crates/monitor-core/src/control.rs"])
        self.assertEqual(tier, "full")
        self.assertIn("ANTC_REVISION", reasons[0])


class GitTests(unittest.TestCase):
    """The diff side of auto, in a scratch repository."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run_git("init", "-q", "-b", "main")
        self.write("src/antinomie/monitor/crates/monitor-core/src/control.rs", "pub const REVISION: u32 = 17;\n")
        self.write("src/antinomie/monitor/crates/monitor-core/src/other.rs", "// ANTC_REVISION 17 is mentioned\n")
        self.write("docs/a.md", "a\n")
        self.run_git("add", ".")
        self.run_git("commit", "-q", "-m", "base")
        self.run_git("update-ref", "refs/remotes/origin/release-1.0.0", "HEAD")
        self.run_git("update-ref", "refs/remotes/origin/release-0.9.0", "HEAD")
        self.run_git("checkout", "-q", "-b", "work")
        self.patch = mock_root(vm, self.root)
        self.addCleanup(self.patch)

    def run_git(self, *args):
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        *args], check=True, capture_output=True)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def decide(self):
        paths, revision = vm.changed_against("origin/release-1.0.0")
        return vm.choose_tier(paths, revision)

    def test_no_change_is_quick(self):
        self.assertEqual(self.decide()[0], "quick")

    def test_working_tree_and_untracked_files_count(self):
        self.write("docs/a.md", "changed\n")
        self.assertEqual(self.decide()[0], "quick")
        self.write("src/antinomie/transport/new.c", "int x;\n")
        tier, reasons = self.decide()
        self.assertEqual(tier, "full")
        self.assertIn("transport/new.c", reasons[0])

    def test_committed_patch_counts(self):
        self.write("src/antinomie/core/6.12/0001-a.patch", "x\n")
        self.run_git("add", ".")
        self.run_git("commit", "-q", "-m", "patch")
        self.assertEqual(self.decide()[0], "full")

    def test_revision_line_counts_but_mention_does_not(self):
        self.write("src/antinomie/monitor/crates/monitor-core/src/other.rs", "// ANTC_REVISION 17 is mentioned twice\n")
        self.assertEqual(self.decide()[0], "quick")
        self.write("src/antinomie/monitor/crates/monitor-core/src/control.rs", "pub const REVISION: u32 = 18;\n")
        tier, reasons = self.decide()
        self.assertEqual(tier, "full")
        self.assertIn("control.rs changes ANTC_REVISION", reasons[-1])

    def test_default_ref_is_the_nearest_release_branch(self):
        self.assertEqual(vm.default_against(), "origin/release-1.0.0")
        self.run_git("update-ref", "refs/remotes/origin/release-0.9.0", "HEAD")
        self.write("docs/b.md", "b\n")
        self.run_git("add", ".")
        self.run_git("commit", "-q", "-m", "more")
        # Both are equally behind: the newer version wins.
        self.assertEqual(vm.default_against(), "origin/release-1.0.0")
        self.run_git("update-ref", "refs/remotes/origin/release-0.9.0", "HEAD")
        self.assertEqual(vm.default_against(), "origin/release-0.9.0")


def mock_root(module, root):
    old = module.ROOT
    module.ROOT = root
    return lambda: setattr(module, "ROOT", old)


class ArgumentTests(unittest.TestCase):
    def test_quick(self):
        args = vm.parse(["quick", "base"])
        self.assertEqual((args.tier, args.base, args.retries, args.only, args.skip), ("quick", "base", 0, [], []))

    def test_full_options(self):
        args = vm.parse(["full", "b", "--old-base", "o", "--old-host", "abc123", "--only", "debug-p2",
                         "--only", "uring-status", "--skip", "snapshot", "--retries", "2", "--rerun-failed"])
        self.assertEqual((args.old_base, args.old_host, args.only, args.skip, args.retries, args.rerun_failed),
                         ("o", "abc123", ["debug-p2", "uring-status"], ["snapshot"], 2, True))

    def test_auto_against(self):
        self.assertEqual(vm.parse(["auto", "b", "--against", "origin/main"]).against, "origin/main")

    def test_rejects_bad_input(self):
        for argv in ([], ["slow", "b"], ["quick"], ["quick", "b", "--retries", "x"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                with open(os.devnull, "w") as quiet, unittest.mock.patch("sys.stderr", quiet):
                    vm.parse(argv)
        with self.assertRaises(SystemExit):
            vm.parse(["quick", "b", "--retries", "-1"])
        with self.assertRaises(SystemExit):
            vm.parse(["quick", "b", "--old-host", "main"])


class PlanTests(unittest.TestCase):
    def ctx(self):
        out = Path("/out")
        return {"out": out, "base": Path("/base"), "old_base": Path("/old"), "new": Path("/new"),
                "fix": out / "fixtures", "old": Path("/oldhost"), "old_ok": True}

    def test_quick_is_the_three_oracle_groups(self):
        checks = vm.plan("quick", self.ctx())
        self.assertEqual([c.name for c in checks], ["conf-quick"])
        self.assertEqual(checks[0].argv[-1], "user,root,threads")

    def test_full_contains_quick_and_both_interop_directions(self):
        names = [c.name for c in vm.plan("full", self.ctx())]
        self.assertEqual(names[0], "conf-quick")
        for name in ("conf-stress-light", "conf-stress-heavy", "conf-stress-extreme", "conf-stress-lossy",
                     "debug-p2", "debug-p3", "audit-stop", "audit-core", "uring-status",
                     "uring-boots", "uring-legacy", "tracer-record", "tracer-legacy", "tracer-qa",
                     "debugger-live", "stealth", "snapshot", "io-old-new-p3", "io-new-old-audit"):
            self.assertIn(name, names)
        self.assertEqual(len(names), len(set(names)))

    def test_interop_pairs_old_host_with_new_base_and_back(self):
        by_name = {c.name: c.argv for c in vm.plan("full", self.ctx())}
        self.assertTrue(by_name["io-old-new-p3"][0].startswith("/oldhost/"))
        self.assertIn("/base", by_name["io-old-new-p3"])
        self.assertTrue(by_name["io-new-old-audit"][0].startswith("/new/"))
        self.assertIn("/old", by_name["io-new-old-audit"])

    def test_every_vm_check_has_its_own_data_folder(self):
        folders = [a for c in vm.plan("full", self.ctx()) if c.vm and c.argv
                   for a in c.argv if a.startswith("/out/runs/")]
        self.assertEqual(len(folders), len(set(folders)))

    def test_select_rejects_unknown_names(self):
        checks = vm.plan("full", self.ctx())
        self.assertEqual([c.name for c in vm.select(checks, ["debug-p2"], [])], ["debug-p2"])
        self.assertNotIn("snapshot", [c.name for c in vm.select(checks, [], ["snapshot"])])
        with self.assertRaises(vm.Failure):
            vm.select(checks, ["nope"], [])

    def test_missing_prerequisites_skip(self):
        ctx = {**self.ctx(), "old_base": None, "old_ok": False}
        by_name = {c.name: c for c in vm.plan("full", ctx)}
        self.assertIn("--old-base", vm.missing(by_name["uring-legacy"], ctx))
        self.assertIsNone(vm.missing(by_name["debug-p2"], ctx))


class TracerQaTests(unittest.TestCase):
    """Triage QA reads tracer-record's runs; it must not pass over a failed one."""

    def run_qa(self, record, log_text="", data=True):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "logs").mkdir()
            ctx = {**PlanTests().ctx(), "out": out, "results": {}}
            if record:
                log = out / "logs" / "tracer-record.try2.log"
                log.write_text(log_text.replace("DATA", tmp))
                ctx["results"]["tracer-record"] = {"status": record, "log": str(log)}
            check = next(c for c in vm.plan("full", ctx) if c.name == "tracer-qa")
            return vm.command_for(check, ctx, None)

    LOG = "RUN writes=DATA/tracer_record_1/run\nFIXTURE_SHA256 ab\nPASS record\n"

    def test_a_failed_or_missing_record_is_an_error(self):
        for status in (None, "FAIL", "TIMEOUT", "ERROR", "SKIP"):
            with self.subTest(status=status), self.assertRaisesRegex(vm.Failure, "tracer-record"):
                self.run_qa(status, self.LOG)

    def test_a_passed_record_is_read_from_its_last_attempt(self):
        for status in ("PASS", "FLAKY"):
            argv, env = self.run_qa(status, self.LOG)
            self.assertIn("recorded_tracer_triage", argv)
            self.assertTrue(env["ANTINOMIE_TRACER_RUNS"].startswith("writes="))
            self.assertEqual(env["ANTINOMIE_TRACER_FIXTURE_SHA256"], "ab")

    def test_the_last_runs_result_counts_when_this_run_has_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text('{"tracer-record": {"status": "FAIL", "log": "/l"}}')
            ctx = {**PlanTests().ctx(), "out": out, "results": {}}
            self.assertEqual(vm.input_result(ctx, "tracer-record")["status"], "FAIL")
            self.assertIsNone(vm.input_result(ctx, "debug-p2"))


class DiskTests(unittest.TestCase):
    def args(self, *extra):
        return vm.parse(["quick", "b", *extra])

    def test_defaults_and_options(self):
        args = self.args("--min-free", "/tmp:3", "--min-free", "/:1", "--max-used-gb", "100")
        self.assertEqual((args.max_used_gb, args.min_free, args.keep_data), (100, ["/tmp:3", "/:1"], False))
        self.assertEqual(self.args().max_used_gb, 380)

    def test_bad_min_free_is_refused(self):
        for spec in ("/tmp", "/tmp:x", ":5"):
            with self.subTest(spec=spec), self.assertRaises(SystemExit), \
                    unittest.mock.patch("sys.stderr", io.StringIO()):
                self.args("--min-free", spec)

    def test_guard_refuses_a_full_disk(self):
        self.assertIsNone(vm.disk_problem(self.args("--min-free", "/tmp:0")))
        self.assertIn("over the limit", vm.disk_problem(self.args("--max-used-gb", "0", "--min-free", "/tmp:0")))
        self.assertIn("under the limit", vm.disk_problem(self.args("--min-free", "/tmp:99999999")))
        with self.assertRaises(vm.Failure):
            vm.disk_guard(self.args("--min-free", "/tmp:99999999"))

    def test_stress_groups_are_separate_checks(self):
        names = [c.name for c in vm.plan("full", PlanTests().ctx()) if c.name.startswith("conf-stress")]
        self.assertEqual(len(names), 4)

    def test_cleanup_removes_bulk_and_keeps_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            conf = out / "runs/conf-quick"
            for sub in ("groups/user", "render", "trace"):
                (conf / sub).mkdir(parents=True)
                (conf / sub / "f").write_text("x")
            plain = out / "runs/debug-p2"
            plain.mkdir(parents=True)
            (out / "xdg/debug-p2/home").mkdir(parents=True)
            vm.clean_check_data(out, "conf-quick")
            vm.clean_check_data(out, "debug-p2")
            self.assertFalse((conf / "groups").exists() or (conf / "render").exists())
            self.assertTrue((conf / "trace/f").exists())
            self.assertFalse(plain.exists() or (out / "xdg/debug-p2").exists())


class IsolationTests(unittest.TestCase):
    def test_environment_stays_under_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = vm.private_env(Path(tmp), "x")
            for var in ("HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
                self.assertTrue(env[var].startswith(tmp), var)

    def test_output_inside_the_apps_folders_is_refused(self):
        home = Path.home()
        for private in ("antinomie", ".local/share/antinomie", ".config/antinomie"):
            with self.assertRaises(vm.Failure):
                vm.forbid_user_folders(home / private / "out")
        vm.forbid_user_folders(Path("/tmp/vm-regress-out"))

    def test_root_home_and_xdg_folders_are_refused(self):
        home = Path.home()
        for bad in (Path("/"), home, home / ".local", home / ".local/share", home / ".config", home / ".cache",
                    Path(os.environ.get("XDG_DATA_HOME") or home / ".local/share"),
                    Path(os.environ.get("XDG_DATA_HOME") or home / ".local/share") / "antinomie", Path("/home")):
            with self.subTest(out=str(bad)), self.assertRaises(vm.Failure):
                vm.forbid_user_folders(bad)
        vm.forbid_user_folders(home / "vm-regress-out")

    def test_a_link_to_a_protected_folder_is_refused_by_its_real_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "out"
            link.symlink_to(Path.home())
            with self.assertRaises(vm.Failure):
                vm.forbid_user_folders(link)
            data = Path(tmp) / "xdgdata"
            (data / "antinomie").mkdir(parents=True)
            with unittest.mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(data)}):
                with self.assertRaises(vm.Failure):
                    vm.forbid_user_folders(data / "antinomie" / "out")
                with self.assertRaises(vm.Failure):
                    vm.forbid_user_folders(data)


class SafeRemoveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.out = base / "out"
        self.out.mkdir()
        self.outside = base / "outside"
        (self.outside / "victim").mkdir(parents=True)
        (self.outside / "victim" / "keep").write_text("x")

    def test_plain_folder_is_removed(self):
        target = self.out / "runs" / "a"
        target.mkdir(parents=True)
        (target / "f").write_text("x")
        vm.safe_rmtree(target, self.out)
        self.assertFalse(target.exists())
        vm.safe_rmtree(target, self.out)  # already gone: fine

    def test_linked_parent_is_refused_and_nothing_outside_is_touched(self):
        (self.out / "runs").symlink_to(self.outside)
        with self.assertRaises(vm.Failure):
            vm.safe_rmtree(self.out / "runs" / "victim", self.out)
        self.assertTrue((self.outside / "victim" / "keep").exists())

    def test_linked_check_data_never_reaches_the_target(self):
        (self.out / "xdg").symlink_to(self.outside)
        with self.assertRaises(vm.Failure):
            vm.clean_check_data(self.out, "victim")
        self.assertTrue((self.outside / "victim" / "keep").exists())

    def test_link_as_last_component_is_unlinked_not_followed(self):
        (self.out / "runs").mkdir()
        (self.out / "runs" / "a").symlink_to(self.outside / "victim")
        vm.safe_rmtree(self.out / "runs" / "a", self.out)
        self.assertFalse((self.out / "runs" / "a").is_symlink())
        self.assertTrue((self.outside / "victim" / "keep").exists())

    def test_outside_path_and_root_itself_are_refused(self):
        for bad in (self.outside / "victim", self.out, self.out / ".." / "outside"):
            with self.subTest(path=str(bad)), self.assertRaises(vm.Failure):
                vm.safe_rmtree(bad, self.out)
        self.assertTrue((self.outside / "victim" / "keep").exists())


class StopTreeTests(unittest.TestCase):
    """A killed check takes its whole tree with it, and only its own tree."""

    SCRIPT = (
        "import os, signal, subprocess, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "kid = subprocess.Popen([sys.executable, '-c', 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)'])\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    # a grandchild that is re-parented to init once its parent is gone\n"
        "    if os.fork() == 0:\n"
        "        signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "        open(sys.argv[1], 'w').write(str(os.getpid()) + ' ' + str(kid.pid))\n"
        "        time.sleep(300)\n"
        "    os._exit(0)\n"
        "os.waitpid(pid, 0)\n"
        "time.sleep(300)\n"
    )

    def test_grandchildren_die_after_the_child_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            pids = Path(tmp) / "pids"
            bystander = subprocess.Popen(["sleep", "300"])
            self.addCleanup(bystander.wait)
            self.addCleanup(bystander.kill)
            child = subprocess.Popen([sys.executable, "-c", self.SCRIPT, str(pids)], start_new_session=True)
            for _ in range(100):
                if pids.exists() and pids.read_text().count(" "):
                    break
                time.sleep(0.1)
            orphan, kid = (int(x) for x in pids.read_text().split())
            self.assertTrue(vm.alive(orphan, None) and vm.alive(kid, None))
            vm.stop_tree(child, grace=1)
            for _ in range(50):
                if not vm.alive(orphan, None) and not vm.alive(kid, None):
                    break
                time.sleep(0.1)
            self.assertFalse(vm.alive(orphan, None), "re-parented grandchild survived")
            self.assertFalse(vm.alive(kid, None), "child of the child survived")
            self.assertTrue(vm.alive(bystander.pid, None), "a process outside the tree was killed")


class ToolCopyTests(unittest.TestCase):
    def fixture(self, root):
        source, out = root / "source", root / "out"
        for tool in ("gef", "pwndbg"):
            folder = source / "tools" / tool
            folder.mkdir(parents=True)
            (folder / "entry").write_text(tool)
            (folder / "runtime").write_text("required library")
        return vm.argparse.Namespace(debugger_tools=str(source)), out

    def test_resuming_replaces_an_incomplete_copy(self):
        with tempfile.TemporaryDirectory() as name:
            args, out = self.fixture(Path(name))
            partial = out / "debugger-data/tools/pwndbg"
            partial.mkdir(parents=True)
            (partial / "entry").write_text("incomplete")
            data = vm.tools_dir(args, out)
            self.assertEqual((data / "tools/pwndbg/runtime").read_text(), "required library")
            self.assertEqual((partial / "entry").read_text(), "pwndbg")
            self.assertTrue((partial / ".vm-regress-copy-complete").is_file())

    def test_a_failed_copy_does_not_publish_or_destroy_the_previous_folder(self):
        with tempfile.TemporaryDirectory() as name:
            args, out = self.fixture(Path(name))
            partial = out / "debugger-data/tools/gef"
            partial.mkdir(parents=True)
            (partial / "entry").write_text("previous")
            with unittest.mock.patch.object(vm.shutil, "copytree", side_effect=OSError("interrupted")):
                with self.assertRaises(OSError):
                    vm.tools_dir(args, out)
            self.assertEqual((partial / "entry").read_text(), "previous")
            self.assertFalse((partial / ".vm-regress-copy-complete").exists())
            self.assertEqual(list((out / "debugger-data/tools").iterdir()), [partial])

    def test_a_complete_copy_is_reused(self):
        with tempfile.TemporaryDirectory() as name:
            args, out = self.fixture(Path(name))
            vm.tools_dir(args, out)
            with unittest.mock.patch.object(vm.shutil, "copytree", side_effect=AssertionError("copied twice")):
                vm.tools_dir(args, out)

    def test_a_linked_tool_parent_is_refused_before_any_write(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            args, out = self.fixture(root)
            private = root / "private"
            private.mkdir()
            (private / "keep").write_text("untouched")
            out.mkdir()
            (out / "debugger-data").symlink_to(private, target_is_directory=True)
            with self.assertRaises(vm.Failure):
                vm.tools_dir(args, out)
            self.assertEqual(list(private.iterdir()), [private / "keep"])
            self.assertEqual((private / "keep").read_text(), "untouched")


class ReportTests(unittest.TestCase):
    def result(self, name, status, attempts=None):
        value = {"name": name, "status": status, "seconds": 61.0, "log": f"/out/logs/{name}.log"}
        if attempts:
            value["attempts"] = attempts
        return value

    def test_exit_code(self):
        ok = {"a": self.result("a", "PASS"), "b": self.result("b", "FLAKY")}
        self.assertEqual(vm.exit_code(ok, ["a", "b"]), 0)
        for status in ("FAIL", "TIMEOUT", "ERROR", "SKIP"):
            self.assertEqual(vm.exit_code({"a": self.result("a", status)}, ["a"]), 1)
        self.assertEqual(vm.exit_code({}, ["a"]), 1)

    def test_report_lists_every_attempt(self):
        attempts = [{"attempt": 1, "status": "FAIL", "seconds": 30, "log": "/l1"},
                    {"attempt": 2, "status": "PASS", "seconds": 31, "log": "/l2"}]
        text = vm.report({"a": self.result("a", "FLAKY", attempts)}, ["a", "b"], "head")
        self.assertIn("attempt 1: FAIL", text)
        self.assertIn("attempt 2: PASS", text)
        self.assertIn("not run", text)
        self.assertIn("FLAKY", text.splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
