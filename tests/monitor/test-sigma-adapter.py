#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adapter tests use SQLite itself; pySigma conversion is an optional integration."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sigma_adapter", ROOT / "src/antinomie/monitor/crates/monitor-core/assets/sigma_scan.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AdapterTests(unittest.TestCase):
    def journal(self, events, version=2):
        """Write a journal of (category, fields[, inferred]) events and load it into SQLite."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        identity = {"vm_id": "vm", "boot_id": "boot", "run_id": "run", "root_cookie": 7}
        records = [{"kind": "header", "format_version": version, "identity": identity}]
        for index, (category, fields, *inferred) in enumerate(events):
            event = {"category": category, "fields": fields, "evidence": {"kind": "call", "stream": 1, "cookie": 7, "call": index + 1}}
            if inferred:
                event["_inferred"] = inferred[0]
            records.append({"kind": "event", "event": event})
        records.append({"kind": "end", "events": len(events), "omitted": 0, "complete": True})
        path = Path(directory.name) / "events.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
        connection = sqlite3.connect(":memory:", cached_statements=0)
        self.addCleanup(connection.close)
        adapter.load_events(connection, path, identity)
        return connection

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
        total, evidence, evaluated, missing, event_ids, _ = adapter.matching_rows(connection, [query], "process_creation")
        self.assertEqual((total, evaluated, missing), (1, 2, 1))
        self.assertEqual(evidence[0]["call"], 2 ** 64 - 1)
        self.assertEqual(event_ids, [1], "the exact journal ordinal of the matched event")

    def test_version_one_and_two_journals_load_and_unknown_versions_do_not(self):
        self.journal([("process_creation", {"Image": "/bin/sh"})], version=1)
        self.journal([("process_creation", {"Image": "/bin/sh"}, ["Image"])], version=2)
        with self.assertRaises(ValueError):
            self.journal([("process_creation", {"Image": "/bin/sh"})], version=3)

    def test_matches_on_inferred_fields_are_counted_and_missing_parents_are_never_matched(self):
        connection = self.journal([
            ("network_connection", {"DestinationIp": "203.0.113.9", "DestinationHostname": "evil.test", "Initiated": "true"}, ["DestinationHostname"]),
            ("network_connection", {"DestinationIp": "203.0.113.9", "Initiated": "true"}),
            ("process_creation", {"Image": "/bin/ls", "ParentImage": "/bin/sh"}),
            ("process_creation", {"Image": "/bin/ls"}),
        ])
        query = "SELECT * FROM logs WHERE DestinationHostname LIKE '%.test'"
        total, _, evaluated, missing, _, inferred = adapter.matching_rows(connection, [query], "network_connection")
        self.assertEqual((total, evaluated, missing), (1, 1, 1))
        self.assertEqual(inferred, (1, ["destinationhostname"]))
        query = "SELECT * FROM logs WHERE NOT COALESCE(ParentImage LIKE '%/bash', 0)"
        total, _, evaluated, missing, _, inferred = adapter.matching_rows(connection, [query], "process_creation")
        self.assertEqual((total, evaluated, missing, inferred[0]), (1, 1, 1, 0))

    def test_auditd_records_are_matched_by_audit_field_names_as_text(self):
        connection = self.journal([
            ("auditd", {"type": "SYSCALL", "Syscall": "personality", "a0": "40000", "exe": "/tmp/x"}, ["exe"]),
            ("auditd", {"type": "EXECVE", "argc": "2", "a0": "chmod", "a1": "777"}),
            ("auditd", {"type": "PATH", "name": "/etc/ld.so.preload", "nametype": "CREATE"}),
            ("process_creation", {"Image": "/bin/chmod"}),
        ])
        for query, expected in [
            ("SELECT * FROM logs WHERE (type='SYSCALL' COLLATE NOCASE AND SYSCALL='personality' COLLATE NOCASE AND a0=40000)", 1),
            ("SELECT * FROM logs WHERE type='EXECVE' COLLATE NOCASE AND a0='chmod' COLLATE NOCASE AND a1=777", 1),
            ("SELECT * FROM logs WHERE type='PATH' COLLATE NOCASE AND name='/etc/ld.so.preload' COLLATE NOCASE", 1),
            ("SELECT * FROM logs WHERE type='PATH' COLLATE NOCASE AND `key`='x'", 0),
        ]:
            total = adapter.matching_rows(connection, [query], "auditd")[0]
            self.assertEqual(total, expected, query)
        total, _, _, _, _, inferred = adapter.matching_rows(connection, ["SELECT * FROM logs WHERE type='SYSCALL' AND exe LIKE '/tmp/%' ESCAPE '\\'"], "auditd")
        self.assertEqual((total, inferred), (1, (1, ["exe"])))
        # The trace has no audit keys: a rule on one has no events to evaluate.
        _, _, evaluated, _, _, _ = adapter.matching_rows(connection, ["SELECT * FROM logs WHERE type='SYSCALL' AND `key`='network_connect_4'"], "auditd")
        self.assertEqual(evaluated, 0)

    def test_logsource_mapping_covers_auditd_and_keeps_keyword_and_other_services_out(self):
        class Source:
            def __init__(self, category=None, product="linux", service=None):
                self.category, self.product, self.service = category, product, service
        self.assertEqual(adapter.logsource_category(Source(service="auditd")), "auditd")
        self.assertEqual(adapter.logsource_category(Source("process_creation")), "process_creation")
        self.assertIsNone(adapter.logsource_category(Source("process_creation", service="auditd")))
        self.assertIsNone(adapter.logsource_category(Source(service="syslog")))
        self.assertIsNone(adapter.logsource_category(Source()))
        self.assertIsNone(adapter.logsource_category(Source(service="auditd", product="windows")))
        self.assertIsNone(adapter.logsource_category(Source("auditd")))

    def test_multiple_conditions_deduplicate_and_preserve_evidence(self):
        connection, _, _ = self.fixture()
        query = "SELECT * FROM logs WHERE Image LIKE '%/sh'"
        total, evidence, _, _, event_ids, _ = adapter.matching_rows(connection, [query, query], "process_creation")
        self.assertEqual(total, 2)
        self.assertEqual(len(evidence), 2)
        self.assertEqual(event_ids, [1, 2])
        self.assertEqual([item["call"] for item in evidence], [2 ** 64 - 1, 2 ** 64 - 2])

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
        # The two other rules have no matching events in this run; that is a coverage limit.
        self.assertEqual(report["state"], "complete", report)
        self.assertEqual(report["scanned_rules"], 1, report)
        self.assertEqual(report["skipped_rules"], 2, report)
        self.assertEqual(report["coverage"]["evaluated"], 1)
        self.assertEqual(report["coverage"]["no_matching_events"], 2)
        self.assertEqual(report["findings"][0]["title"], "Shell Execution Observed")
        self.assertEqual(report["findings"][0]["count"], 2)
        self.assertEqual(report["findings"][0]["events"], [1, 2])
        self.assertEqual(report["findings"][0]["mitre"], ["T1059.004"])
        self.assertTrue(report["sources"][0]["sha256"])
        self.assertIn("not full compatibility", report["warnings"][0])

    RULE = """title: {title}
id: {ident}
logsource:
  category: {category}
  product: linux
detection:
  selection:
    {field}|endswith: /sh
  condition: selection
level: low
"""

    def scan(self, rules, events=None, complete=True, **limits):
        """Run the adapter over a journal and rule documents (a list of YAML texts)."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        identity = {"vm_id": "vm", "boot_id": "boot", "run_id": "run", "root_cookie": 7}
        events = [("process_creation", {"Image": "/bin/sh"})] * 3 if events is None else events
        records = [{"kind": "header", "format_version": 2, "identity": identity}]
        for index, (category, fields) in enumerate(events):
            records.append({"kind": "event", "event": {"category": category, "fields": fields, "evidence": {"kind": "call", "stream": 1, "cookie": 7, "call": index + 1}}})
        records.append({"kind": "end", "events": len(events), "omitted": 0, "complete": complete})
        path = Path(directory.name) / "events.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
        sources = []
        for index, text in enumerate(rules):
            source = Path(directory.name) / f"rules-{index}.yml"
            source.write_text(text)
            sources.append({"path": str(source), "name": f"rules-{index}.yml"})
        saved = {name: getattr(adapter, name) for name in limits}
        try:
            for name, value in limits.items():
                setattr(adapter, name, value)
            return adapter.scan({"identity": identity, "sigma_sources": sources}, path)
        finally:
            for name, value in saved.items():
                setattr(adapter, name, value)

    def rule(self, title="Shell", category="process_creation", field="Image", ident=None):
        return self.RULE.format(title=title, ident=ident or uuid.uuid5(uuid.NAMESPACE_DNS, title), category=category, field=field)

    def counts(self, report):
        coverage = report["coverage"]
        return tuple(coverage[key] for key in ("evaluated", "no_matching_events", "unsupported_category", "backend", "syntax"))

    def test_coverage_helper_counts_every_rule_and_lists_a_bounded_number(self):
        report = {"coverage": adapter.new_coverage()}
        for index in range(adapter.COVERAGE_LIST_LIMIT + 5):
            adapter.note_not_applicable(report, "syntax", f"file-{index}", "bad")
        coverage = report["coverage"]
        self.assertEqual(coverage["syntax"], adapter.COVERAGE_LIST_LIMIT + 5)
        self.assertEqual((len(coverage["listed"]), coverage["unlisted"]), (adapter.COVERAGE_LIST_LIMIT, 5))
        self.assertEqual(coverage["listed"][0], {"reason": "syntax", "rule": "file-0", "detail": "bad"})

    @unittest.skipUnless(importlib.util.find_spec("sigma"), "optional local pySigma integration")
    def test_rules_that_do_not_apply_are_counted_and_the_scan_stays_complete(self):
        report = self.scan([
            self.rule("Matches"),
            self.rule("No events", category="dns_query", field="QueryName"),
            self.rule("Registry", category="registry_set"),
            "title: [unterminated\n",
            self.rule("Bad field", field="UncapturedField"),
        ])
        self.assertEqual(report["state"], "complete", report)
        self.assertEqual(self.counts(report), (1, 1, 1, 1, 1), report["coverage"])
        self.assertEqual(report["scanned_rules"], 1)
        self.assertEqual(report["findings"][0]["count"], 3)
        reasons = sorted(item["reason"] for item in report["coverage"]["listed"])
        self.assertEqual(reasons, ["backend", "no_matching_events", "syntax", "unsupported_category"])
        self.assertIsNone(report["coverage"]["evidence_preview_limit"])
        self.assertEqual(report["format_version"], adapter.REPORT_FORMAT_VERSION)
        self.assertIn("not full compatibility", report["warnings"][0], "the coverage warning stays")

    @unittest.skipUnless(importlib.util.find_spec("sigma"), "optional local pySigma integration")
    def test_no_events_with_the_required_fields_is_not_a_conversion_failure(self):
        report = self.scan([self.rule("Needs a command line", field="CommandLine")], events=[("process_creation", {"Image": "/bin/sh"})])
        coverage = report["coverage"]
        self.assertEqual((coverage["no_matching_events"], coverage["backend"], coverage["syntax"], coverage["unsupported_category"]), (1, 0, 0, 0))
        self.assertNotIn("partial", report["state"])

    @unittest.skipUnless(importlib.util.find_spec("sigma"), "optional local pySigma integration")
    def test_the_evidence_preview_cap_is_a_note_and_counts_stay_complete(self):
        report = self.scan([self.rule()], events=[("process_creation", {"Image": "/bin/sh"})] * 5, MAX_EVIDENCE=2)
        self.assertEqual(report["state"], "complete", report)
        self.assertEqual(report["findings"][0]["count"], 5)
        self.assertEqual(len(report["findings"][0]["evidence"]), 2)
        self.assertEqual(report["omitted_evidence"], 3)
        self.assertEqual(report["coverage"]["evidence_preview_limit"], 2)
        self.assertTrue(any("match counts are complete" in warning for warning in report["warnings"]), report["warnings"])

    @unittest.skipUnless(importlib.util.find_spec("sigma"), "optional local pySigma integration")
    def test_real_incompleteness_is_still_partial(self):
        incomplete = self.scan([self.rule()], complete=False)
        self.assertEqual(incomplete["state"], "partial", "the journal is truncated or incomplete")
        budget = self.scan([self.rule("First"), self.rule("Second")], MAX_RULES=1)
        self.assertEqual(budget["state"], "partial", "the rule budget is exhausted")
        self.assertEqual(budget["scanned_rules"], 1)
        timed_out = self.scan([self.rule()], EVALUATION_SECONDS=-1)
        self.assertIn("stopped", " ".join(timed_out["warnings"]), "the time budget ends the evaluation")
        self.assertNotEqual(timed_out["state"], "complete")
        late = self.scan([self.rule("First"), self.rule("Second")], MAX_FINDINGS=1)
        self.assertEqual(late["state"], "partial", "a match that cannot be reported is incomplete")

    @unittest.skipUnless(os.environ.get("ANTINOMIE_SIGMA_RULES"), "community Sigma tree not selected")
    def test_community_candidates_reconcile_backend_conversion(self):
        paths = sorted(Path(os.environ["ANTINOMIE_SIGMA_RULES"]).rglob("*.yml"))
        counts, reasons = adapter.classify_rules(paths)
        self.assertTrue(counts["reconciled"], (counts, reasons))
        self.assertGreater(counts["files"], 0)
        self.assertEqual(
            counts["category_rejected"] + counts["category_accepted"],
            counts["rules"],
        )
        self.assertEqual(
            counts["backend_rejected"] + counts["backend_converted"],
            counts["category_accepted"],
        )
        self.assertEqual(
            counts["schema_rejected"] + counts["schema_accepted"],
            counts["backend_converted"],
        )


if __name__ == "__main__":
    unittest.main()
