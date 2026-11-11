#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Tests of scripts/check-command-new.py (the A21 allow-list gate): the real
tree passes, and a new unlisted process start is caught in every spelling,
while test code, comments and strings are not counted."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-command-new.py"
spec = importlib.util.spec_from_file_location("gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CRATE = "src/antinomie/monitor/crates/service/src"


def tree(files, allow=""):
    d = pathlib.Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (d / "allow.txt").write_text(allow)
    return d


def run(d):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--root", str(d), "--list", str(d / "allow.txt")],
        capture_output=True, text=True,
    )


class Gate(unittest.TestCase):
    def test_the_repository_passes(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_new_unlisted_call_fails(self):
        d = tree({f"{CRATE}/new.rs": "use std::process::Command;\nfn f() { Command::new(\"sh\"); }\n"})
        r = run(d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("new.rs", r.stderr)

    def test_other_spellings_fail(self):
        for body in [
            "fn f() { std::process::Command::new(\"x\").spawn().ok(); }",
            "use std::process::Command as C;\nfn f() { C::new(\"x\"); }",
            "use std::process::{Command, Stdio};\nfn f() { Command::new(\"x\"); }",
            "use std::os::unix::process::CommandExt;\nfn f(mut c: std::process::Command) { c.exec(); }",
            "fn f() { unsafe { libc::execv(p, a); } }",
        ]:
            with self.subTest(body=body):
                self.assertEqual(run(tree({f"{CRATE}/x.rs": body})).returncode, 1)

    def test_a_listed_call_passes_and_one_more_fails(self):
        src = "use std::process::Command;\nfn f() { Command::new(\"a\"); }\n"
        allow = f"{CRATE}/x.rs 1 a reviewed hook\n"
        self.assertEqual(run(tree({f"{CRATE}/x.rs": src}, allow)).returncode, 0)
        more = src + "fn g() { Command::new(\"b\"); }\n"
        r = run(tree({f"{CRATE}/x.rs": more}, allow))
        self.assertEqual(r.returncode, 1)
        self.assertIn("allow-list says 1", r.stderr)

    def test_a_stale_entry_fails(self):
        r = run(tree({f"{CRATE}/x.rs": "fn f() {}\n"}, f"{CRATE}/x.rs 1 gone\n"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("lower or remove", r.stderr)

    def test_tests_comments_strings_and_other_command_types_are_not_counted(self):
        quiet = {
            f"{CRATE}/a.rs": "use std::process::Command;\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t() { Command::new(\"sleep\"); }\n}\n",
            f"{CRATE}/b.rs": "use std::process::Command;\n// Command::new(\"x\")\nfn f() { let _ = \"Command::new(x)\"; let _ = r#\"Command::new(\"y\")\"#; }\n",
            f"{CRATE}/c.rs": "struct Command;\nimpl Command { fn new(_: u8) -> Self { Self } }\nfn f() { Command::new(1); }\n",
            f"{CRATE}/tests/d.rs": "use std::process::Command;\nfn f() { Command::new(\"x\"); }\n",
            f"{CRATE}/e_tests.rs": "use std::process::Command;\nfn f() { Command::new(\"x\"); }\n",
        }
        r = run(tree(quiet))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_code_after_a_test_module_is_still_counted(self):
        src = "#[cfg(test)]\nmod tests { fn t() { let s = \"}\"; } }\nuse std::process::Command;\nfn f() { Command::new(\"x\"); }\n"
        self.assertEqual(run(tree({f"{CRATE}/x.rs": src})).returncode, 1)


if __name__ == "__main__":
    unittest.main()
