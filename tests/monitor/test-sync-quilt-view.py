#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""scripts/sync-quilt-view.py: the Quilt view of the guest series lists every patch."""
import importlib.util
import tempfile
import unittest
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
    def test_the_repository_view_lists_every_patch_of_the_series(self):
        self.assertEqual(sync.main(["--check"]), 0)
        series = (sync.VIEW / "series").read_text().split()
        self.assertEqual(len(series), len(list(sync.CORE.glob("*.patch"))))
        self.assertEqual(series[0][:4], "0001")
        self.assertTrue(all((sync.VIEW / name).is_file() for name in series))

    def test_a_patch_with_and_without_a_body_becomes_a_dep3_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            for body, text in (("First paragraph\nwraps.\n\nSecond.\n\n", "First paragraph wraps.  Second."), ("", "")):
                path = Path(tmp) / "0007-x.patch"
                path.write_text(MAIL.format(body=body))
                name, out = sync.view_text(path)
                self.assertEqual(name, "0007-antinomie-do-one-thing-and-another.patch")
                head, _, diff = out.partition("\n---\n")
                self.assertIn("Description: antinomie: do one thing and another\n", head)
                self.assertIn("Author: A Person <a@example.org>\n", head)
                self.assertIn("Last-Update: 2026-10-20\n", head)
                self.assertTrue(head.rstrip().endswith(text or "Last-Update: 2026-10-20"))
                # git show leaves out format-patch's signature.
                self.assertTrue(diff.startswith("diff --git a/f.c b/f.c"))
                self.assertFalse(diff.rstrip().endswith("2.47.0"))
                self.assertTrue(diff.endswith("+int g(void);\n"))


if __name__ == "__main__":
    unittest.main()
