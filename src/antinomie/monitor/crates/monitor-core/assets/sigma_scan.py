#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline pySigma/SQLite adapter. Called only by the isolated detector worker."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sqlite3
import sys
import time

MAX_EVENTS = 1_000_000
MAX_FINDINGS = 10_000
MAX_EVIDENCE = 10_000
MAX_RULE_SIZE = 1024 * 1024
# Evaluation budget: rules and seconds. Reaching either leaves the scan partial.
MAX_RULES = 4096
EVALUATION_SECONDS = 90
SUPPORTED_CATEGORIES = {"process_creation", "process_termination", "file_event", "file_delete", "file_rename", "file_access", "dns_query", "http_request", "network_connection", "antinomie_bpf", "antinomie_file_metadata", "auditd"}
# Journal format versions this adapter reads. Version 2 added the per-event `_inferred` list; version 3 the credential and hash fields.
JOURNAL_VERSIONS = {1, 2, 3}
# `service: auditd` rules evaluate the auditd-style records, stored under this one category.
AUDITD_SERVICE = "auditd"
SUPPORTED_SERVICES = {"", "antinomie", AUDITD_SERVICE}
# Field names auditd uses. Stored as TEXT so a rule's number (`a0: 40000`) equals the recorded text.
# `Syscall` is shared with the Sysmon-style events: auditd rules write it `SYSCALL`, and names are case-insensitive.
AUDITD_FIELDS = {"type", "exe", "comm", "name", "nametype", "key", "exit", "success", "pid", "ppid", "saddr", "argc", "cwd", "proctitle", "uid", "euid", "suid", "fsuid", "gid", "egid", "sgid", "fsgid", "auid", "ses"} | {"a" + str(index) for index in range(16)}
SCHEMA = {"Image", "CommandLine", "ProcessId", "ThreadId", "TargetFilename", "SourceFilename", "QueryName", "QueryType", "ResponseCode", "DestinationIp", "DestinationPort", "HttpMethod", "HttpHost", "HttpUri", "Syscall", "Operation", "Result", "TransferredSize", "BpfCommand", "Mode", "Setuid", "Initiated", "ParentImage", "ParentCommandLine", "ParentProcessId", "CurrentDirectory", "DestinationHostname", "SourceIp", "SourcePort", "Protocol", "IsNewFile", "User", "LogonId", "Hashes", "HashSkipped"} | AUDITD_FIELDS
MAX_INFERRED = 64
# Individual rules named in `coverage.listed`; the counts cover all of them.
COVERAGE_LIST_LIMIT = 200
# Report format 1 adds `coverage`: rules that do not apply to this run are counted there and do not make the scan partial.
REPORT_FORMAT_VERSION = 1


class NotApplicable(Exception):
    """A rule this run cannot use. A coverage limit, not an incomplete scan."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


class PartialLimit(Exception):
    """A limit that drops matches this scan would otherwise have reported."""


def new_coverage():
    return {"evaluated": 0, "no_matching_events": 0, "unsupported_category": 0, "backend": 0, "syntax": 0, "listed": [], "unlisted": 0, "evidence_preview_limit": None}


def note_not_applicable(report, reason, rule, detail):
    """Count one rule that did not apply, and list it while the list has room."""
    coverage = report["coverage"]
    coverage[reason] += 1
    if len(coverage["listed"]) < COVERAGE_LIST_LIMIT:
        coverage["listed"].append({"reason": reason, "rule": str(rule)[:512], "detail": str(detail)[:1024]})
    else:
        coverage["unlisted"] += 1


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def create_logs(connection):
    columns = ",".join(quoted(name) + (" TEXT" if name in AUDITD_FIELDS else "") + " COLLATE NOCASE" for name in sorted(SCHEMA))
    connection.execute("CREATE TABLE logs(_event_id INTEGER PRIMARY KEY, _category TEXT NOT NULL, _evidence TEXT NOT NULL, _inferred TEXT," + columns + ")")


def logsource_category(logsource):
    """The journal category a rule's logsource reads, or None when this adapter has no events for it."""
    category = (logsource.category or "").lower()
    product = (logsource.product or "").lower()
    service = (logsource.service or "").lower()
    if product not in {"", "linux"} or service not in SUPPORTED_SERVICES:
        return None
    if service == AUDITD_SERVICE:
        return AUDITD_SERVICE if category in {"", AUDITD_SERVICE} else None
    return category if category in SUPPORTED_CATEGORIES and category != AUDITD_SERVICE else None


def load_events(connection, path, expected):
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA cache_size=-2048")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA max_page_count=65536")
    create_logs(connection)
    count = 0
    footer = None
    with Path(path).open("rb") as source:
        header = json.loads(source.readline(65537))
        if header.get("format_version") not in JOURNAL_VERSIONS or header.get("identity") != expected:
            raise ValueError("normalized event identity mismatch")
        for line in iter(lambda: source.readline(65537), b""):
            if len(line) > 65536:
                raise ValueError("normalized event exceeds 64 KiB")
            record = json.loads(line)
            if footer is not None:
                raise ValueError("normalized events follow completion record")
            if record.get("kind") == "end":
                footer = record
                continue
            if record.get("kind") != "event" or count >= MAX_EVENTS:
                raise ValueError("normalized event count/type exceeds bound")
            event = record["event"]
            fields = event["fields"]
            if event["category"] not in SUPPORTED_CATEGORIES:
                raise ValueError("unknown normalized category")
            names, values = [], []
            for name, value in fields.items():
                if name not in SCHEMA:
                    continue
                if not isinstance(value, (str, int, float, bool)) or isinstance(value, int) and not -(2 ** 63) <= value < 2 ** 63:
                    continue
                names.append(name)
                values.append(value)
            inferred = event.get("_inferred") or []
            if not isinstance(inferred, list) or len(inferred) > MAX_INFERRED or not all(isinstance(name, str) for name in inferred):
                raise ValueError("normalized event _inferred is not a bounded list of field names")
            columns = ["_category", "_evidence", "_inferred"] + names
            connection.execute("INSERT INTO logs(" + ",".join(quoted(name) for name in columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")", [event["category"], json.dumps(event["evidence"]), json.dumps(inferred) if inferred else None] + values)
            count += 1
    if footer is None or footer.get("events") != count:
        raise ValueError("normalized event index is unfinished or inconsistent")
    connection.commit()
    reasons = footer.get("reasons")
    reasons = [reason for reason in reasons if isinstance(reason, str)][:16] if isinstance(reasons, list) else []
    return count, bool(footer.get("complete")) and footer.get("omitted", 0) == 0, reasons


def supplied_authors(rule):
    value = getattr(rule, "author", None)
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item).strip() for item in value if str(item).strip())
    text = str(value).strip()
    return "" if text in {"", "None"} else text


def select_query(connection, query):
    prefix = "SELECT * FROM logs WHERE "
    if not query.startswith(prefix) or len(query) > 1024 * 1024:
        raise ValueError("correlation/custom output is not supported by this event adapter")
    if not query.isascii():
        raise ValueError("non-ASCII rule literals require Unicode case folding unavailable in SQLite NOCASE")
    query = "SELECT _event_id FROM logs WHERE " + query[len(prefix):]
    fields = set()

    def authorize(action, first, second, _database, _trigger):
        if action == sqlite3.SQLITE_READ and first == "logs":
            if second not in SCHEMA and second not in {"_event_id", "_category", "_evidence", "_inferred"}:
                return sqlite3.SQLITE_DENY
            if second in SCHEMA:
                fields.add(second)
            return sqlite3.SQLITE_OK
        if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    connection.set_authorizer(authorize)
    connection.execute("EXPLAIN QUERY PLAN " + query).fetchall()
    return query, fields


def inferred_note(connection, selection, parameters, fields):
    """Matched events whose rule fields include a value the journal marks inferred, and which fields."""
    wanted = {name.lower() for name in fields}
    events, names = 0, set()
    for inferred, count in connection.execute("SELECT _inferred, COUNT(*) FROM (" + selection + ") WHERE _inferred IS NOT NULL GROUP BY _inferred", parameters):
        used = wanted & {name.lower() for name in json.loads(inferred)}
        if used:
            events += count
            names |= used
    return events, sorted(names)


def matching_rows(connection, queries, category):
    converted = [select_query(connection, query) for query in queries]
    fields = set().union(*(fields for _, fields in converted))
    # This conservative evidence guard is deliberate: unavailable telemetry is
    # not a confirmed absent/null field, including inside a negated condition.
    guard = " AND ".join(quoted(name) + " IS NOT NULL" for name in sorted(fields)) or "1"
    union = " UNION ".join(query for query, _ in converted)
    eligible = connection.execute("SELECT COUNT(*) FROM logs WHERE _category=? AND (" + guard + ")", (category,)).fetchone()[0]
    observed = connection.execute("SELECT COUNT(*) FROM logs WHERE _category=?", (category,)).fetchone()[0]
    selection = "SELECT _event_id, _evidence, _inferred FROM logs WHERE _category=? AND (" + guard + ") AND _event_id IN (" + union + ")"
    total = connection.execute("SELECT COUNT(*) FROM (" + selection + ")", (category,)).fetchone()[0]
    # `_event_id` is the one-based position in the journal, so a finding can name the exact event it matched.
    rows = connection.execute(selection + " ORDER BY _event_id LIMIT ?", (category, min(total, MAX_EVIDENCE))).fetchall()
    inferred = inferred_note(connection, selection, (category,), fields) if total else (0, [])
    return total, [json.loads(row[1]) for row in rows], eligible, observed - eligible, [row[0] for row in rows], inferred


def attack_tags(tags):
    result = []
    for tag in tags:
        text = str(tag).upper().removeprefix("ATTACK.")
        if len(text) in (5, 9) and text.startswith("T") and text[1:5].isdigit() and (len(text) == 5 or text[5] == "." and text[6:].isdigit()):
            result.append(text)
    return sorted(set(result))


_sigma_progress_at = 0.0


def note_sigma(events_path, index, total, title):
    """Write one coalesced progress file beside the event journal."""
    global _sigma_progress_at
    now = time.monotonic()
    if index not in (1, total) and now - _sigma_progress_at < 0.25:
        return
    _sigma_progress_at = now
    payload = {
        "target": {
            "kind": "sigma_rule",
            "index": index,
            "total": max(total, 1),
            "title": str(title)[:240],
        },
        "rules_loaded": total,
    }
    path = Path(events_path).with_name("progress.json")
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(path)


def rule_yaml(data, rule):
    text = data.decode("utf-8", errors="replace")
    ident = str(getattr(rule, "id", "") or "")
    title = str(getattr(rule, "title", "") or "")
    parts = []
    current = []
    for line in text.splitlines(keepends=True):
        if line.strip() == "---" and current:
            parts.append("".join(current))
            current = []
            continue
        current.append(line)
    if current:
        parts.append("".join(current))
    chosen = text
    for part in parts:
        if ident and ident in part and "id:" in part:
            chosen = part
            break
    else:
        for part in parts:
            if title and title in part:
                chosen = part
                break
    encoded = chosen.strip().encode("utf-8", errors="replace")
    if len(encoded) > 8192:
        encoded = encoded[:8192]
    return encoded.decode("utf-8", errors="ignore")


def scan(request, events_path):
    report = {"format_version": REPORT_FORMAT_VERSION, "coverage": new_coverage(), "engine": "sigma", "identity": request["identity"], "state": "complete", "sources": [], "findings": [], "scanned_rules": 0, "skipped_rules": 0, "skipped": [], "omitted_evidence": 0, "warnings": [], "source_digest": request.get("source_digest"), "category_accepted": 0, "backend_rejected": 0, "missing_field_events": 0, "category_rejected": 0, "syntax_rejected": 0, "evidence_rejected": 0}
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.sqlite import sqliteBackend
        version = importlib.metadata.version("pysigma")
        backend_version = importlib.metadata.version("pysigma-backend-sqlite")
        if version.split(".")[0] != "2":
            raise ImportError("this adapter requires pySigma 2.x")
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        report["state"] = "unavailable"
        report["warnings"] = ["Local pySigma 2.x and its SQLite backend are required: " + str(error)]
        return report
    connection = sqlite3.connect(str(Path(events_path).with_suffix(".sqlite")), cached_statements=0)
    deadline = time.monotonic() + EVALUATION_SECONDS
    connection.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
    evidence_count = 0
    try:
        report["scanned_objects"], complete, reasons = load_events(connection, events_path, request["identity"])
        if not complete:
            report["state"] = "partial"
            if reasons:
                report["warnings"].append("Partial: the rules ran on part of the evidence: " + "; ".join(reasons) + ".")
            else:
                report["warnings"].append("Partial: the saved events are incomplete, so the rules ran on part of the evidence.")
        try:
            import re2
            connection.create_function("regexp", 2, lambda pattern, value: value is not None and re2.search(pattern, str(value)) is not None)
        except ImportError:
            pass  # REGEXP queries fail explicitly; other rules remain usable.
        backend = sqliteBackend(collate_nocase=True)
        prepared = []
        rule_total = 0
        for source in request["sigma_sources"]:
            path = Path(source["path"])
            data = path.read_bytes()
            if len(data) > MAX_RULE_SIZE:
                raise ValueError("Sigma rule exceeds 1 MiB")
            sha256 = hashlib.sha256(data).hexdigest()
            report["sources"].append({"name": source["name"], "version": "sha256:" + sha256 + "; pySigma " + version + "; SQLite backend " + backend_version, "license": "Per-rule license; local rules are not redistributed", "sha256": sha256, "data": "Captured Linux exec/file/network operations, auditd-style records, DNS/HTTP and BPF observations; missing and inferred fields are not hidden"})
            try:
                collection = SigmaCollection.from_yaml(data.decode("utf-8"))
            except Exception as error:
                report["syntax_rejected"] += 1
                report["skipped_rules"] += 1
                note_not_applicable(report, "syntax", source["name"], str(error)[:400])
                if len(report["skipped"]) < 1000:
                    report["skipped"].append(source["name"] + ": syntax: " + str(error)[:400])
                continue
            rules = list(collection.rules)
            rule_total += len(rules)
            prepared.append((source, data, sha256, rules))
        seen = 0
        partial_limit_noted = False
        failure_noted = False
        for source, data, sha256, rules in prepared:
            for rule in rules:
                seen += 1
                note_sigma(events_path, seen, rule_total, getattr(rule, "title", "") or "")
                if report["scanned_rules"] + report["skipped_rules"] >= MAX_RULES:
                    report["state"] = "partial"
                    report["warnings"].append("Partial: the " + str(MAX_RULES) + "-rule evaluation budget was reached; the remaining rules were not evaluated.")
                    return report
                if time.monotonic() > deadline:
                    raise TimeoutError("Sigma rule evaluation reached its 90 second budget")
                try:
                    logsource = rule.logsource
                    category = logsource_category(logsource)
                    if category is None:
                        report["category_rejected"] += 1
                        raise NotApplicable("unsupported_category", "unsupported logsource: " + str(logsource))
                    report["category_accepted"] += 1
                    try:
                        queries = backend.convert(SigmaCollection([rule]))
                    except Exception as error:
                        report["backend_rejected"] += 1
                        raise NotApplicable("backend", "backend rejected the rule: " + str(error)[:300]) from error
                    if not queries:
                        report["backend_rejected"] += 1
                        raise NotApplicable("backend", "rule produced no supported query")
                    try:
                        total, evidence, evaluated, missing, event_ids, inferred = matching_rows(connection, queries, category)
                    except sqlite3.OperationalError as error:
                        if "interrupted" in str(error):
                            raise TimeoutError("Sigma rule evaluation reached its 90 second budget") from error
                        report["backend_rejected"] += 1
                        raise NotApplicable("backend", str(error)) from error
                    except (ValueError, sqlite3.Error) as error:
                        # Correlation or custom output, non-ASCII literals, a field outside the captured schema.
                        report["backend_rejected"] += 1
                        raise NotApplicable("backend", str(error)) from error
                    if missing:
                        report["missing_field_events"] += int(missing)
                        if len(report["skipped"]) < 1000:
                            report["skipped"].append(str(rule.id or rule.title) + f": {missing} events lack fields used by this rule; missing values were not invented")
                    if not evaluated:
                        report["evidence_rejected"] += 1
                        raise NotApplicable("no_matching_events", "no captured events with all required fields")
                    report["scanned_rules"] += 1
                    report["coverage"]["evaluated"] += 1
                    if total:
                        room = max(0, MAX_EVIDENCE - evidence_count)
                        retained = evidence[:room]
                        evidence_count += len(retained)
                        report["omitted_evidence"] += total - len(retained)
                        if total > len(retained):
                            report["coverage"]["evidence_preview_limit"] = MAX_EVIDENCE
                        if len(report["findings"]) >= MAX_FINDINGS:
                            raise PartialLimit("matched-rule preview limit reached")
                        level = getattr(rule.level, "name", "informational").lower()
                        refs = getattr(rule, "references", None) or []
                        ref_text = "; ".join(str(item) for item in refs if str(item).strip())
                        description = " ".join(str(getattr(rule, "description", None) or "").split())[:2000]
                        details = (description + " " if description else "") + "Evaluated against normalized captured Linux events; joined argv is not original shell quoting."
                        if inferred[0]:
                            details += f" {inferred[0]} of {total} matching events rely on inferred fields ({', '.join(inferred[1])}); an inferred value comes from tracking state or correlation, not from one captured call."
                        if ref_text:
                            details += " References: " + ref_text
                        details = details.encode("utf-8")[:8000].decode("utf-8", errors="ignore")
                        report["findings"].append({"rule_id": str(rule.id or (source["name"] + ":" + rule.title)), "title": rule.title, "severity": level, "source": source["name"] + " sha256:" + sha256, "license": str(getattr(rule, "license", None) or "Not supplied by rule"), "author": supplied_authors(rule), "mitre": attack_tags(rule.tags or []), "count": total, "evidence": retained, "events": event_ids[:room], "details": details, "rule_text": rule_yaml(data, rule)})
                except TimeoutError:
                    raise
                except Exception as error:
                    title = str(getattr(rule, "title", source["name"]))
                    report["skipped_rules"] += 1
                    if isinstance(error, NotApplicable):
                        note_not_applicable(report, error.reason, title, str(error)[:400])
                    elif isinstance(error, PartialLimit):
                        # A match this scan found cannot be reported: that is incomplete.
                        report["state"] = "partial"
                        if not partial_limit_noted:
                            partial_limit_noted = True
                            report["warnings"].append("Partial: matches of rule '" + title[:120] + "' and later rules could not be reported because the " + str(MAX_FINDINGS) + "-matched-rule limit was reached.")
                    else:
                        # Not a reason a rule may be set aside: the scan did not finish evaluating it.
                        report["state"] = "partial"
                        if not failure_noted:
                            failure_noted = True
                            report["warnings"].append("Partial: rule '" + title[:120] + "' failed during evaluation (" + str(error)[:200] + "); failed rules are listed under skipped rules.")
                    if len(report["skipped"]) < 1000:
                        report["skipped"].append(title + ": " + str(error)[:400])
        if not report["scanned_rules"]:
            report["state"] = "unavailable"
            report["warnings"].append("No compatible rule could evaluate captured fields.")
        if report["coverage"]["evidence_preview_limit"]:
            report["warnings"].append("Evidence preview limited to " + str(MAX_EVIDENCE) + " locations; match counts are complete.")
    except TimeoutError:
        report["state"] = "partial" if report["scanned_rules"] else "unavailable"
        report["warnings"].append("Partial: evaluation stopped at its " + str(EVALUATION_SECONDS) + " second budget after " + str(report["scanned_rules"]) + " rules; the remaining rules were not evaluated.")
    except Exception as error:
        report["state"] = "partial" if report["scanned_rules"] else "unavailable"
        report["warnings"].append("Sigma evaluation stopped: " + str(error)[:512])
    finally:
        connection.close()
    return report


def classify_rules(paths):
    """Classify rule files with pySigma/SQLite. Category acceptance is not compatibility."""
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import sqliteBackend
    backend = sqliteBackend(collate_nocase=True)
    counts = {"files": 0, "syntax_rejected": 0, "rules": 0, "category_rejected": 0, "category_accepted": 0, "backend_rejected": 0, "backend_converted": 0, "schema_rejected": 0, "schema_accepted": 0}
    reasons = {key: [] for key in ("syntax", "logsource", "backend", "schema")}
    connection = sqlite3.connect(":memory:")
    create_logs(connection)
    try:
        import re2
        connection.create_function("regexp", 2, lambda pattern, value: value is not None and re2.search(pattern, str(value)) is not None)
    except ImportError:
        pass
    for path in paths:
        counts["files"] += 1
        try:
            collection = SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8", errors="replace"))
        except Exception as error:
            counts["syntax_rejected"] += 1
            if len(reasons["syntax"]) < 30:
                reasons["syntax"].append(Path(path).name + ": " + str(error)[:240])
            continue
        for rule in collection.rules:
            counts["rules"] += 1
            logsource = rule.logsource
            if logsource_category(logsource) is None:
                counts["category_rejected"] += 1
                if len(reasons["logsource"]) < 30:
                    reasons["logsource"].append(str(rule.title) + ": " + str(logsource))
                continue
            counts["category_accepted"] += 1
            try:
                queries = backend.convert(SigmaCollection([rule]))
            except Exception as error:
                counts["backend_rejected"] += 1
                if len(reasons["backend"]) < 30:
                    reasons["backend"].append(str(rule.title) + ": " + str(error)[:240])
                continue
            if not queries:
                counts["backend_rejected"] += 1
                if len(reasons["backend"]) < 30:
                    reasons["backend"].append(str(rule.title) + ": no supported query")
                continue
            counts["backend_converted"] += 1
            try:
                for query in queries:
                    select_query(connection, query)
            except (ValueError, sqlite3.Error) as error:
                counts["schema_rejected"] += 1
                if len(reasons["schema"]) < 30:
                    reasons["schema"].append(str(rule.title) + ": " + str(error)[:240])
                continue
            counts["schema_accepted"] += 1
    connection.close()
    counts["reconciled"] = (
        counts["category_rejected"] + counts["category_accepted"] == counts["rules"]
        and counts["backend_rejected"] + counts["backend_converted"] == counts["category_accepted"]
        and counts["schema_rejected"] + counts["schema_accepted"] == counts["backend_converted"]
    )
    counts["note"] = "schema_accepted means the SQLite backend query uses only adapter fields. It is not per-run evidence compatibility."
    return counts, reasons


def main():
    request = json.loads(Path(sys.argv[2]).read_text())
    result = scan(request, sys.argv[1])
    encoded = json.dumps(result)
    if len(encoded.encode()) > 32 * 1024 * 1024:
        raise ValueError("Sigma report exceeds 32 MiB")
    Path(sys.argv[3]).write_text(encoded)


if __name__ == "__main__":
    main()
