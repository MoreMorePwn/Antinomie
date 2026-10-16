#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adapter tests use SQLite itself; pySigma conversion is an optional integration."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sigma_adapter", ROOT / "src/antinomie/monitor/crates/monitor-core/assets/sigma_scan.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AdapterTests(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        identity = {"vm_id": "vm", "boot_id": "boot", "run_id": "run", "root_cookie": 7}
        records = [{"kind": "header", "format_version": 1, "identity": identity}]
        for index, fields in enumerate(({"Image": "/bin/sh", "CommandLine": "sh -c test"}, {"Image": "/bin/sh"}, {"Image": "/usr/bin/true", "CommandLine": "true"})):
            records.append({"kind": "event", "event": {"category": "process_creation", "fields": fields, "evidence": {"kind": "call", "stream": 1, "cookie": 7, "call": 2 ** 64 - 1 - index}}})
        records.append({"kind": "end", "events": 3, "omitted": 0, "complete": True})
        path = Path(directory.name) / "events.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
        connection = sqlite3.connect(":memory:", cached_statements=0)
        self.addCleanup(connection.close)
        adapter.load_events(connection, path, identity)
        return connection, path, identity

    def test_missing_command_line_cannot_match_a_negated_condition(self):
        connection, _, _ = self.fixture()
        query = "SELECT * FROM logs WHERE Image LIKE '%/sh' AND NOT COALESCE(CommandLine LIKE '%evil%', 0)"
        total, evidence, evaluated, missing = adapter.matching_rows(connection, [query], "process_creation")
        self.assertEqual((total, evaluated, missing), (1, 2, 1))
        self.assertEqual(evidence[0]["call"], 2 ** 64 - 1)

    def test_multiple_conditions_deduplicate_and_preserve_evidence(self):
        connection, _, _ = self.fixture()
        query = "SELECT * FROM logs WHERE Image LIKE '%/sh'"
        total, evidence, _, _ = adapter.matching_rows(connection, [query, query], "process_creation")
        self.assertEqual(total, 2)
        self.assertEqual(len(evidence), 2)

    def test_identity_mismatch_and_mutating_or_unknown_queries_are_rejected(self):
        connection, path, identity = self.fixture()
        with self.assertRaises(ValueError):
            adapter.select_query(connection, "DELETE FROM logs")
        with self.assertRaises(sqlite3.Error):
            adapter.select_query(connection, "SELECT * FROM logs WHERE UncapturedUser='root'")
        other = sqlite3.connect(":memory:")
        self.addCleanup(other.close)
        with self.assertRaises(ValueError):
            adapter.load_events(other, path, {**identity, "run_id": "another"})

    @unittest.skipUnless(importlib.util.find_spec("sigma"), "optional local pySigma integration")
    def test_real_pysigma_conversion_scans_compatible_rules_and_reports_missing_sources(self):
        _, path, identity = self.fixture()
        rules = ROOT / "tests/monitor/fixtures/sigma-sample.yml"
        report = adapter.scan({"identity": identity, "sigma_sources": [{"path": str(rules), "name": "Antinomie Sigma / MIT"}]}, path)
        self.assertEqual(report["state"], "partial", report)
        self.assertEqual(report["scanned_rules"], 1, report)
        self.assertEqual(report["skipped_rules"], 2, report)
        self.assertEqual(report["findings"][0]["title"], "Shell Execution Observed")
        self.assertEqual(report["findings"][0]["count"], 2)
        self.assertEqual(report["findings"][0]["mitre"], ["T1059.004"])
        self.assertTrue(report["sources"][0]["sha256"])


if __name__ == "__main__":
    unittest.main()
