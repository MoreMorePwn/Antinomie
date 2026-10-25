#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""scripts/sync-quilt-view.py: the Quilt view is regenerated from the guest series."""
import importlib.util
import io
import tempfile
import unittest
import unittest.mock
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/sync-quilt-view.py"
spec = importlib.util.spec_from_file_location("sync_quilt_view", SCRIPT)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)

MAIL = """From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001
From: A Person <a@example.org>
Date: Tue, 20 Oct 2026 13:32:29 +0700
Subject: [PATCH] antinomie: do one thing and
 another

{body}---
 f.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/f.c b/f.c
index 111..222 100644
--- a/f.c
+++ b/f.c
@@ -1 +1,2 @@ int f(void)
 int f(void);
+int g(void);
--\x20
2.47.0

"""


class ViewTests(unittest.TestCase):
    def test_the_repository_view_is_the_series(self):
        self.assertEqual(sync.main(["--check"]), 0)
        series = sync.listed(sync.VIEW / "series")
        self.assertEqual(len(series), len(list(sync.CORE.glob("*.patch"))))
        self.assertEqual(series[0][:4], "0001")
        self.assertTrue(all((sync.VIEW / name).is_file() for name in series))
        # The series is grouped by topic under comment headings.
        self.assertIn("# ", (sync.VIEW / "series").read_text())

    def test_a_patch_with_and_without_a_body_becomes_a_dep3_patch(self):
        long_description = " First paragraph\n wraps.\n .\n Second.\n"
        with tempfile.TemporaryDirectory() as tmp:
            for body, text in (("First paragraph\nwraps.\n\nSecond.\n\n", long_description), ("", "")):
                path = Path(tmp) / "0007-x.patch"
                path.write_text(MAIL.format(body=body))
                name, out = sync.view_text(path)
                self.assertEqual(name, "0007-antinomie-do-one-thing-and-another.patch")
                head, _, diff = out.partition("\n---\n")
                self.assertTrue(head.startswith(
                    "Description: antinomie: do one thing and another\n" + text + "Author: "))
                self.assertIn("Author: A Person <a@example.org>\n", head)
                self.assertIn("Origin: project\nForwarded: no\n", head)
                self.assertTrue(head.endswith("Last-Update: 2026-10-20\n"))
                # git show leaves out format-patch's signature.
                self.assertTrue(diff.startswith("diff --git a/f.c b/f.c"))
                self.assertFalse(diff.rstrip().endswith("2.47.0"))
                self.assertTrue(diff.endswith("+int g(void);\n"))

    def test_a_last_paragraph_of_dep3_fields_sets_them(self):
        body = "Backported.\n\nOrigin: upstream, commit:0123abcd\nBug: https://example.org/1\n\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "0007-x.patch"
            path.write_text(MAIL.format(body=body))
            head = sync.view_text(path)[1].partition("\n---\n")[0]
            self.assertIn("another\n Backported.\nAuthor: ", head)
            self.assertIn("Origin: upstream, commit:0123abcd\nForwarded: no\n"
                          "Bug: https://example.org/1\nLast-Update: ", head)

    def test_the_view_is_rewritten_from_the_series_and_keeps_its_headings(self):
        with tempfile.TemporaryDirectory() as tmp:
            core, view = Path(tmp) / "core", Path(tmp) / "view"
            core.mkdir()
            view.mkdir()
            for number, subject in (("0001", "one"), ("0003", "three")):
                (core / f"{number}-x.patch").write_text(
                    MAIL.format(body="").replace("do one thing and\n another", subject))
            (view / "0001-antinomie-one.patch").write_text("stale header\n\n---\nold diff\n")
            (view / "0002-antinomie-two.patch").write_text("gone\n")
            (view / "series").write_text("# Heading one\n0001-antinomie-one.patch\n\n"
                                         "# Heading two\n0002-antinomie-two.patch\n")
            with unittest.mock.patch.object(sync, "CORE", core), \
                    unittest.mock.patch.object(sync, "VIEW", view), \
                    unittest.mock.patch("sys.stderr", io.StringIO()) as err:
                self.assertEqual(sync.main(["--check"]), 1)
                self.assertIn("0001-antinomie-one.patch is not what series patch 0001 produces",
                              err.getvalue())
                self.assertIn("0002-antinomie-two.patch has no series patch", err.getvalue())
                with unittest.mock.patch("sys.stdout", io.StringIO()):
                    self.assertEqual(sync.main([]), 0)
                self.assertEqual(sync.main(["--check"]), 0)
            self.assertEqual(sorted(p.name for p in view.glob("*.patch")),
                             ["0001-antinomie-one.patch", "0003-antinomie-three.patch"])
            # A heading whose patch is gone moves down to the next patch.
            self.assertEqual((view / "series").read_text(),
                             "# Heading one\n0001-antinomie-one.patch\n\n"
                             "# Heading two\n0003-antinomie-three.patch\n")
            self.assertEqual((view / "0003-antinomie-three.patch").read_text(),
                             sync.view_text(core / "0003-x.patch")[1])


if __name__ == "__main__":
    unittest.main()
