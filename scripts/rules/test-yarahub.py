#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the YARAhub steps of prepare-catalog.py. No network."""
import importlib.util
import sys
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("prepare_catalog", Path(__file__).with_name("prepare-catalog.py"))
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)


def hub(name, license_name, strings='$a = "x"', condition="$a"):
    lic = f'\n    yarahub_license = "{license_name}"' if license_name else ""
    return f'rule {name}\n{{\n  meta:\n    author = "a"{lic}\n  strings:\n    {strings}\n  condition:\n    {condition}\n}}\n'


FORGE = (
    "/*\n * YARA Rule Set\n * Repository Name: R\n * Repository: https://github.com/e/r\n"
    " *\n * LICENSE\n * MIT License\n */\n\n"
    + 'rule FORGE_One\n{\n  meta:\n    author = "f"\n  strings:\n    $s = "same body"\n  condition:\n    $s\n}\n'
)


class Classify(unittest.TestCase):
    def test_licenses(self):
        members = {
            "a.yar": hub("A", "CC0 1.0"),
            "b.yar": hub("B", "CC BY 4.0", '$b = "b"', "$b"),
            "c.yar": hub("C", "CC BY-SA 4.0", '$c = "c"', "$c"),
            "d.yar": hub("D", "CC BY-NC 4.0", '$d = "d"', "$d"),
            "e.yar": hub("E", "CC BY-NC-ND 4.0", '$e = "e"', "$e"),
            "f.yar": hub("F", None, '$f = "f"', "$f"),
        }
        kept, dropped, unnamed, dups, licenses = pc.classify_yarahub(members, "")
        self.assertEqual(kept, ["a.yar", "b.yar", "c.yar"])
        self.assertEqual((dropped, unnamed, dups), (2, 1, []))
        self.assertEqual(licenses["CC0 1.0"], 1)
        self.assertEqual(licenses["(none)"], 1)

    def test_duplicates_by_name_and_body(self):
        members = {
            "same_body.yar": hub("Renamed", "CC0 1.0", '$s = "same body"', "$s"),
            "same_name.yar": hub("FORGE_One", "CC0 1.0", '$z = "z"', "$z"),
            "fresh.yar": hub("Fresh", "CC0 1.0", '$y = "y"', "$y"),
            "nc_dup.yar": hub("Renamed2", "CC BY-NC 4.0", '$s = "same body"', "$s"),
        }
        kept, dropped, unnamed, dups, _ = pc.classify_yarahub(members, FORGE)
        self.assertEqual(kept, ["fresh.yar"])
        self.assertEqual(dups, ["same_body.yar", "same_name.yar"])
        self.assertEqual(dropped, 1)  # a non-commercial copy counts as a license drop only

    def test_meta_value_reads_the_monitors_form(self):
        block = hub("A", "CC0 1.0").replace('yarahub_license = ', 'yarahub_license =    ')
        self.assertEqual(pc.meta_value(block, ["yarahub_license"]), "CC0 1.0")
        self.assertIsNone(pc.meta_value(hub("A", "n/a"), ["yarahub_license"]))
        self.assertIsNone(pc.meta_value(hub("A", None), ["yarahub_license"]))

    def test_body_key_ignores_meta_and_spacing(self):
        one = hub("X", "CC0 1.0")
        two = hub("Y", "CC BY 4.0").replace("$a = ", "$a   =  ")
        self.assertEqual(pc.rule_body_key(one), pc.rule_body_key(two))


if __name__ == "__main__":
    sys.exit(unittest.main())
