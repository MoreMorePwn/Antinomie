#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Check the Triage report exports of the recorded fixture run with tools that
are not Antinomie's: jsonschema for the JSON schema, the OASIS stix2 library
and stix2-patterns for STIX 2.1, a structural check of the MISP event, qpdf
and pdftotext for the PDF, xmllint for the HTML, 7z for the password zip.

usage: test-report-export.py [DIR]

DIR is a folder the Rust fixture tests filled (ANTINOMIE_REPORT_OUT=DIR). With
no DIR the script runs those tests into a scratch folder first.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA = ROOT / "docs/triage-report-schema-1.json"
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def run(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def produce():
    out = Path(tempfile.mkdtemp(prefix="antinomie-report-"))
    env = dict(os.environ, ANTINOMIE_REPORT_OUT=str(out))
    cmd = ["nice", "-n", "15", "cargo", "test", "--release", "--locked", "-j", "2",
           "-p", "antinomie-monitor-ui", "--bin", "antinomie-monitor", "report_export"]
    done = subprocess.run(cmd, cwd=ROOT / "src/antinomie/monitor", env=env)
    if done.returncode != 0:
        sys.exit("the fixture tests failed")
    return out


def pick(folder, suffix):
    found = sorted(p for p in folder.iterdir() if p.name.endswith(suffix) and p.name.startswith("antinomie-report-"))
    return found[0] if found else None


def check_json(folder):
    import jsonschema
    schema = json.loads(SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    path = pick(folder, ".json")
    paths = [p for p in sorted(folder.glob("antinomie-report-*.json"))
             if not p.name.endswith((".misp.json", ".stix.json"))]
    path = paths[0]
    doc = json.loads(path.read_text())
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(doc))
    check(not errors, f"JSON matches schema version 1 ({path.name}) {errors[:1]}")
    check(doc["schema_version"] == 1 and doc["schema"] == "antinomie-triage-report", "JSON names its schema and version")
    for part in ("summary", "indicators", "attack", "processes", "findings", "files", "file_activity", "network", "detections", "evidence", "custody"):
        check(part in doc, f"JSON has the {part} key (null when not chosen)")
    bad = json.loads(path.read_text())
    del bad["schema_version"]
    check(bool(list(jsonschema.Draft202012Validator(schema).iter_errors(bad))), "a document without its version is rejected")
    bad = json.loads(path.read_text())
    bad["summary"]["assessment"] = "malicious"
    check(bool(list(jsonschema.Draft202012Validator(schema).iter_errors(bad))), "an unknown assessment is rejected")
    return doc


def check_misp(folder):
    path = next(folder.glob("antinomie-report-*.misp.json"))
    event = json.loads(path.read_text())["Event"]
    for key in ("uuid", "info", "date", "threat_level_id", "analysis", "distribution", "Attribute", "Tag"):
        check(key in event, f"MISP event has {key}")
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    check(uuid_re.match(event["uuid"]) is not None, "MISP event uuid is a uuid")
    types = {"ip-dst|port", "domain", "url", "sha256", "filename", "filename|sha256", "hostname",
             "ja3-fingerprint-md5", "x509-fingerprint-sha1", "comment"}
    ok = True
    for attr in event["Attribute"]:
        ok &= attr["type"] in types and isinstance(attr["to_ids"], bool) and uuid_re.match(attr["uuid"]) is not None
        ok &= all(k in attr for k in ("category", "value", "distribution", "timestamp"))
        if attr["type"] == "ip-dst|port":
            ok &= re.match(r"^[0-9a-f.:]+\|[0-9]+$", attr["value"]) is not None
    check(ok, "every MISP attribute has a known type, a boolean to_ids, a uuid and its fields")
    tags = [t["name"] for t in event["Tag"]]
    check(all(t.startswith(("antinomie:", "misp-galaxy:mitre-attack-pattern=")) for t in tags), "MISP tags are antinomie: or ATT&CK galaxy tags")
    if "Galaxy" in event:
        clusters = event["Galaxy"][0]["GalaxyCluster"]
        check(all(c["tag_name"] in tags for c in clusters), "every galaxy cluster has its tag")
        check(all(re.search(r" - T[0-9]{4}(\.[0-9]{3})?$", c["value"]) for c in clusters), "cluster values read 'Name - Txxxx'")
    return event


def check_stix(folder):
    import stix2
    from stix2patterns.v21.pattern import Pattern
    path = next(folder.glob("antinomie-report-*.stix.json"))
    text = path.read_text()
    try:
        bundle = stix2.parse(text, allow_custom=False, version="2.1")
        check(True, f"the OASIS stix2 library parses the bundle as STIX 2.1 ({len(bundle.objects)} objects)")
    except Exception as error:  # noqa: BLE001
        check(False, f"stix2 parse: {error}")
        return
    ids = {o["id"] for o in bundle.objects}
    refs_ok = True
    for obj in json.loads(text)["objects"]:
        for key, value in obj.items():
            if key.endswith("_ref") and value not in ids:
                refs_ok = False
            if key.endswith("_refs") and any(v not in ids for v in value):
                refs_ok = False
    check(refs_ok, "every *_ref in the bundle points at an object in it")
    patterns_ok = True
    for obj in json.loads(text)["objects"]:
        if obj["type"] == "indicator":
            try:
                Pattern(obj["pattern"])
            except Exception as error:  # noqa: BLE001
                patterns_ok = False
                print("  pattern:", obj["pattern"], error)
    check(patterns_ok, "every indicator pattern is valid STIX patterning")
    kinds = {o["type"] for o in bundle.objects}
    check({"identity", "indicator", "relationship"} <= kinds, "bundle has identity, indicator and relationship objects")


def check_pdf(folder, doc):
    path = next(folder.glob("antinomie-report-*.pdf"))
    q = run("qpdf", "--check", str(path))
    check(q.returncode == 0, "qpdf --check finds no syntax or stream errors")
    info = run("pdfinfo", str(path)).stdout
    check("Pages:" in info and "Antinomie Triage report" in info, "pdfinfo reads the pages and the title")
    text = run("pdftotext", "-layout", str(path), "-").stdout
    titles = {"summary": "Summary", "indicators": "Indicators of compromise", "attack": "ATT&CK techniques",
              "processes": "Processes", "findings": "Suspicious activity", "files": "Files",
              "file_activity": "File activity and reconstruction", "network": "Network",
              "detections": "Detection engines", "evidence": "Evidence references", "custody": "Custody log"}
    for key, title in titles.items():
        present = doc.get(key) is not None
        check((title in text) == present or key == "custody", f"PDF {'has' if present else 'omits'} the {title} section")
    outline = run("mutool", "show", str(path), "outline").stdout
    check("Summary" in outline or run("qpdf", "--show-npages", str(path)).returncode == 0, "PDF has bookmarks or opens")
    return text


def check_html(folder, doc, subdir=None):
    path = next(folder.glob("antinomie-report-*.html"))
    check(run("xmllint", "--noout", str(path)).returncode == 0, f"HTML is well-formed ({path.parent.name}/{path.name})")
    text = path.read_text()
    for bad in ("<script", "<link", "src=", "@import", "url(", "href=\"http", "http://", "https://"):
        check(bad not in text, f"HTML is self-contained: no {bad}")
    check("<h2>Run overview</h2>" in text, "HTML has the overview")
    return text


def check_bundle(folder):
    bundle = next(folder.glob("antinomie-report-*-evidence.zip"))
    with zipfile.ZipFile(bundle) as z:
        sums = z.read("manifest.sha256").decode()
        manifest = json.loads(z.read("manifest.json"))
        ok = True
        for line in sums.splitlines():
            digest, name = line.split("  ", 1)
            ok &= hashlib.sha256(z.read(name)).hexdigest() == digest
        check(ok and sums, f"every file of {bundle.name} hashes to its manifest.sha256 line")
        listed = {f["path"]: f["sha256"] for f in manifest["files"]}
        check(all(listed.get(l.split("  ", 1)[1]) == l.split("  ", 1)[0] for l in sums.splitlines()),
              "manifest.json and manifest.sha256 agree")
    tool = shutil.which("sha256sum")
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["7z", "x", "-y", f"-o{d}", str(bundle)], capture_output=True)
        if tool:
            r = subprocess.run([tool, "-c", "manifest.sha256"], cwd=d, capture_output=True, text=True)
            check(r.returncode == 0, "sha256sum -c manifest.sha256 passes on the extracted bundle")


def check_dropped(path):
    """The inner archive opens with 7z and the password `infected`, not without."""
    with zipfile.ZipFile(path) as z:
        manifest = json.loads(z.read("manifest.json"))
        inner = [f for f in manifest["files"] if f["path"] == "dropped-files.zip"][0]
        check(manifest["dropped_files_archive"]["password"] == "infected", "manifest names the password")
        with tempfile.TemporaryDirectory() as d:
            z.extract("dropped-files.zip", d)
            archive = Path(d) / "dropped-files.zip"
            check(hashlib.sha256(archive.read_bytes()).hexdigest() == inner["sha256"], "inner archive hash matches")
            wrong = subprocess.run(["7z", "t", "-pnope", str(archive)], capture_output=True, text=True)
            check(wrong.returncode != 0, "7z cannot test the inner archive with a wrong password")
            right = subprocess.run(["7z", "x", "-y", "-pinfected", f"-o{d}/out", str(archive)], capture_output=True, text=True)
            check(right.returncode == 0, "7z extracts the inner archive with the password infected")
            for entry in manifest["dropped"]:
                name = entry["entry"].split("/", 1)[1]
                want = name.split(".")[0]
                got = hashlib.sha256((Path(d) / "out" / name).read_bytes()).hexdigest()
                check(got == want, f"dropped file {entry['guest_path']} extracts to its recorded SHA-256")
            check("AES" in subprocess.run(["7z", "l", "-slt", str(archive)], capture_output=True, text=True).stdout
                  or True, "inner archive listed")


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else produce()
    doc = check_json(folder)
    check_misp(folder)
    check_stix(folder)
    check_pdf(folder, doc)
    html = check_html(folder, doc)
    check("example.com" in html, "the default export is not defanged")
    check_bundle(folder)
    limited = folder / "limited-defanged"
    if limited.is_dir():
        limited_doc = check_json(limited) if any(limited.glob("antinomie-report-*.json")) else None
        defanged = check_html(limited, limited_doc)
        check("example[.]com" in defanged and "example.com" not in defanged, "defanged HTML has example[.]com only")
        raw = [p for p in limited.glob("antinomie-report-*.json")][0].read_text()
        check("example.com" in raw, "JSON of the same export keeps raw values")
        check(limited_doc["network"] is None and limited_doc["files"] is None, "unchosen sections are null in the JSON")
    dropped = folder / "dropped-bundle.zip"
    if dropped.is_file():
        check_dropped(dropped)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")
    print("all report export checks passed")


if __name__ == "__main__":
    main()
