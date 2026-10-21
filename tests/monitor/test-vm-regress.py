#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""scripts/vm-regress.py: tier choice, argument parsing and the check plan, without a VM."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
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
        for name in ("conf-stress", "debug-p2", "debug-p3", "audit-stop", "audit-core", "uring-status",
                     "uring-boots", "uring-legacy", "tracer-record", "tracer-legacy", "tracer-qa",
                     "debugger-live", "stealth", "snapshot", "io-old-new-p3", "io-new-old-p3"):
            self.assertIn(name, names)
        self.assertEqual(len(names), len(set(names)))

    def test_interop_pairs_old_host_with_new_base_and_back(self):
        by_name = {c.name: c.argv for c in vm.plan("full", self.ctx())}
        self.assertTrue(by_name["io-old-new-p3"][0].startswith("/oldhost/"))
        self.assertIn("/base", by_name["io-old-new-p3"])
        self.assertTrue(by_name["io-new-old-p3"][0].startswith("/new/"))
        self.assertIn("/old", by_name["io-new-old-p3"])

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
