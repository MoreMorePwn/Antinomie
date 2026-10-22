#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""License-expression regressions: unsupported branches cannot be hidden by AND."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('licenses', ROOT / 'scripts/check-licenses.py')
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


class Expressions(unittest.TestCase):
    def test_alternative_can_select_a_supported_license(self):
        self.assertTrue(licenses.permitted('GPL-2.0-only OR MIT'))
        self.assertTrue(licenses.permitted('MIT/Apache-2.0'))

    def test_required_unsupported_license_rejects_the_expression(self):
        self.assertFalse(licenses.permitted('MIT AND GPL-2.0-only'))
        self.assertFalse(licenses.permitted('(MIT OR Apache-2.0) AND Proprietary'))

    def test_exception_is_not_accepted_independently(self):
        self.assertTrue(licenses.permitted('Apache-2.0 WITH LLVM-exception'))
        self.assertFalse(licenses.permitted('GPL-2.0-only WITH LLVM-exception'))
        self.assertFalse(licenses.permitted('Apache-2.0 WITH Unknown-exception'))

    def test_malformed_expressions_fail_even_on_unused_branches(self):
        for expression in ('MIT OR', 'MIT OR (Apache-2.0', 'MIT bad!', 'MIT AND AND MIT', 'MIT OR ()'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                licenses.permitted(expression)


if __name__ == '__main__':
    unittest.main()
