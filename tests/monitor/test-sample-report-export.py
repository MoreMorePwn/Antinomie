#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Check the sample report exports of the fixture sample with tools that are
not Antinomie's: jsonschema for docs/sample-report-schema-1.json, the OASIS
stix2 library and stix2-patterns for STIX 2.1, a structural check of the MISP
event, an XML parser for the HTML (it is well-formed XML by design), qpdf and
pdftotext for the PDF. A tool that is not installed is skipped.

usage: test-sample-report-export.py [DIR]

DIR is a folder the Rust fixture test filled (ANTINOMIE_SAMPLE_REPORT_OUT=DIR).
With no DIR the script runs that test into a scratch folder first.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA = ROOT / "docs/sample-report-schema-1.json"
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def skip(what):
    print(f"skip {what}")


def have_module(*names):
    import importlib.util
    missing = [n for n in names if importlib.util.find_spec(n) is None]
    if missing:
        skip(f"python module {', '.join(missing)} is not installed")
    return not missing


def run(*args):
    return subprocess.run(args, capture_output=True, text=True)


def produce():
    out = Path(tempfile.mkdtemp(prefix="antinomie-sample-report-"))
    env = dict(os.environ, ANTINOMIE_SAMPLE_REPORT_OUT=str(out))
    cmd = ["nice", "-n", "15", "cargo", "test", "--release", "--locked", "-j", "2",
           "-p", "antinomie-monitor-core", "--lib", "sample_report_fixture_export"]
    if subprocess.run(cmd, cwd=ROOT / "src/antinomie/monitor", env=env).returncode != 0:
        sys.exit("the fixture test failed")
    return out


def pick(folder, suffix, exclude=()):
    found = sorted(p for p in folder.iterdir()
                   if p.name.startswith("antinomie-sample-report-") and p.name.endswith(suffix)
                   and not p.name.endswith(exclude))
    return found[0] if found else None


def check_json(folder):
    path = pick(folder, ".json", (".misp.json", ".stix.json"))
    doc = json.loads(path.read_text())
    check(doc["schema"] == "antinomie-sample-report" and doc["schema_version"] == 1, "JSON names its schema and version")
    if have_module("jsonschema"):
        import jsonschema
        schema = json.loads(SCHEMA.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        v = jsonschema.Draft202012Validator(schema)
        errors = list(v.iter_errors(doc))
        check(not errors, f"JSON matches schema version 1 {errors[:1]}")
        bad = json.loads(path.read_text()); del bad["schema_version"]
        check(bool(list(v.iter_errors(bad))), "a document without its version is rejected")
        bad = json.loads(path.read_text()); bad["runs"][0]["assessment"] = "malicious"
        check(bool(list(v.iter_errors(bad))), "an unknown assessment is rejected")
        bad = json.loads(path.read_text()); bad["sample"]["sha256"] = "xyz"
        check(bool(list(v.iter_errors(bad))), "a malformed sample hash is rejected")
    for hit in doc["detections"]:
        check(all(k in hit for k in ("author", "license", "source", "reference")), f"rule {hit['rule_id']} carries its credit")
    check(len(doc["runs"]) == 3 and doc["custody"]["verified"], "runs and the custody verification are present")
    return doc


def check_misp(folder):
    event = json.loads(pick(folder, ".misp.json").read_text())["Event"]
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    check(all(k in event for k in ("uuid", "info", "date", "threat_level_id", "analysis", "distribution", "Attribute", "Tag")), "MISP event has its keys")
    types = {"ip-dst|port", "domain", "url", "sha256", "sha1", "md5", "tlsh", "filename", "size-in-bytes", "hostname",
             "ja3-fingerprint-md5", "x509-fingerprint-sha1", "filename|sha256", "comment"}
    ok = all(a["type"] in types and isinstance(a["to_ids"], bool) and uuid_re.match(a["uuid"])
             and all(k in a for k in ("category", "value", "distribution", "timestamp")) for a in event["Attribute"])
    check(ok, "every MISP attribute has a known type, boolean to_ids, uuid and fields")
    rules = [a["value"] for a in event["Attribute"] if a["type"] == "comment" and " rule " in a["value"]]
    check(rules and all("Author:" in r and "License:" in r and "Source:" in r for r in rules), "MISP rule comments carry author, licence, source")


def check_stix(folder):
    if not have_module("stix2", "stix2patterns"):
        return
    import stix2
    from stix2patterns.v21.pattern import Pattern
    text = pick(folder, ".stix.json").read_text()
    try:
        bundle = stix2.parse(text, allow_custom=False, version="2.1")
        check(True, f"stix2 parses the bundle as STIX 2.1 ({len(bundle.objects)} objects)")
    except Exception as error:  # noqa: BLE001
        check(False, f"stix2 parse: {error}")
        return
    objs = json.loads(text)["objects"]
    ids = {o["id"] for o in objs}
    check(all((k.endswith("_ref") and v in ids) or (k.endswith("_refs") and all(x in ids for x in v))
              for o in objs for k, v in o.items() if k.endswith(("_ref", "_refs"))), "every *_ref points into the bundle")
    for o in objs:
        if o["type"] == "indicator":
            Pattern(o["pattern"])
    check(True, "every indicator pattern is valid STIX patterning")


def check_html(folder, doc, raw=False):
    path = pick(folder, ".html")
    text = path.read_text()
    try:
        ET.fromstring(text.split("\n", 1)[1])
        check(True, f"HTML is well-formed XML ({path.parent.name}/{path.name})")
    except ET.ParseError as error:
        check(False, f"HTML well-formed: {error}")
    for bad in ("<script", "<link", "src=", "@import", "url(", 'href="http', "http://", "https://"):
        check(bad not in text or (raw and bad in ("http://", "https://")), f"HTML is self-contained: no {bad}")
    check(("203.0.113.5:443" in text) == raw, "HTML defangs unless raw was chosen")
    for h in doc["detections"]:
        check(h["author"] in text or not h["author"], f"HTML names the author of {h['rule_id']}")


def check_markdown(folder, raw=False):
    text = pick(folder, ".md").read_text()
    check(text.startswith("# Antinomie Sample report"), "Markdown has its title")
    check(("203.0.113.5" in text) == raw, "Markdown defangs unless raw was chosen")
    for block in text.split("\n\n"):
        if block.startswith("| "):
            n = {len(re.sub(r"\\\|", "", l).split("|")) for l in block.splitlines()}
            check(len(n) == 1, "a Markdown table has equal cells in every row")
            break


def check_pdf(folder):
    if not shutil.which("qpdf") or not shutil.which("pdftotext"):
        skip("qpdf/pdftotext are not installed")
        return
    path = pick(folder, ".pdf")
    check(run("qpdf", "--check", str(path)).returncode == 0, "qpdf --check passes")
    text = run("pdftotext", "-layout", str(path), "-").stdout
    for title in ("Sample overview", "Static analysis", "Rules that matched", "Runs", "Lineage", "Custody log"):
        check(title in text, f"PDF has the {title} section")


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else produce()
    doc = check_json(folder)
    check_misp(folder)
    check_stix(folder)
    check_html(folder, doc)
    check_markdown(folder)
    check_pdf(folder)
    raw = folder / "raw"
    if raw.is_dir():
        check_html(raw, doc, raw=True)
        check_markdown(raw, raw=True)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")
    print("all sample report export checks passed")


if __name__ == "__main__":
    main()
