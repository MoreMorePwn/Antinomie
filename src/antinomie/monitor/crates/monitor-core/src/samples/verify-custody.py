#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check an Antinomie custody record without Antinomie.

    python3 verify-custody.py custody-record.json     (or the .html export)

Prints "verified" or the first entry that cannot be trusted, and exits 0 when
the chain is intact, 1 when it is not, 2 when the file cannot be read.

What this proves: every entry's hash covers its fields and the hash of the
entry before it, and the library index records agree with the entries. What
it does not prove: that nobody rewrote the whole chain together with the
index. The log is tamper-evident, not tamper-proof. Compare the head hash
printed here with one you kept somewhere else (or check the signature of the
exported file) to rule that out.
"""
import hashlib
import json
import re
import sys

ZERO = "0" * 64


def digest(fields):
    data = b""
    for value in fields:
        raw = value.encode("utf-8")
        data += str(len(raw)).encode() + b":" + raw + b"\n"
    return hashlib.sha256(data).hexdigest()


def entry_hash(sha256, e):
    return digest(["antinomie-custody-entry-v1", sha256, str(e["seq"]), str(e["at_ms"]),
                   e["by"], e["kind"], "1" if e["before_chain"] else "0", e["detail"], e["prev"]])


def index_hash(r):
    return digest(["antinomie-custody-index-v1", str(r["seq"]), str(r["at_ms"]), r["kind"],
                   r["sha256"], str(r["entry_seq"]), r["entry_hash"], r["prev"]])


def load(text):
    marker = re.search(r'<script type="application/json" id="custody-record">(.*?)</script>', text, re.S)
    return json.loads(marker.group(1) if marker else text)


def check(record):
    """Return (entries, head, problem) with problem None or (entry number, text)."""
    if record.get("format") != "antinomie-custody-record" or record.get("version") != 1:
        raise ValueError("not an Antinomie custody record (version 1)")
    sha256 = record["sample"]["sha256"]
    entries = sorted(record["entries"], key=lambda e: e["seq"])
    problem = None

    def note(at, text):
        nonlocal problem
        if problem is None or at < problem[0]:
            problem = (at, text)

    previous, expected = ZERO, 1
    for e in entries:
        if e["seq"] != expected:
            note(expected, "entry %d is missing" % expected)
            break
        if entry_hash(sha256, e) != e["hash"]:
            note(e["seq"], "entry %d was edited after it was written" % e["seq"])
            break
        if e["prev"] != previous:
            if e["seq"] == 1:
                note(1, "the first entry does not start the chain")
            else:
                note(e["seq"] - 1, "entry %d was replaced: entry %d records another hash for it"
                     % (e["seq"] - 1, e["seq"]))
            break
        previous, expected = e["hash"], expected + 1
    count = entries[-1]["seq"] if entries else 0

    heads = []
    for r in sorted(record["index"], key=lambda r: r["seq"]):
        if index_hash(r) != r["hash"]:
            note(max(r["entry_seq"], 1), "index record %d was edited" % r["seq"])
        if r["sha256"] != sha256:
            continue
        if r["kind"] == "purge":
            heads = []
        elif r["kind"] == "head":
            heads.append(r)
    last = max([h["entry_seq"] for h in heads], default=0)
    if not entries and last:
        note(1, "the whole log is gone; the library index recorded %d entries" % last)
    else:
        for h in heads:
            found = [e for e in entries if e["seq"] == h["entry_seq"]]
            if not found:
                note(h["entry_seq"], "entry %d is gone; the library index recorded it" % h["entry_seq"])
            elif found[0]["hash"] != h["entry_hash"]:
                note(h["entry_seq"], "entry %d differs from what the library index recorded" % h["entry_seq"])
        if count > last:
            note(last + 1, "entry %d is not in the library index" % (last + 1))
    return count, (entries[-1]["hash"] if entries else ZERO), problem


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            record = load(handle.read())
        count, head, problem = check(record)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("cannot read the record: %s" % error)
        return 2
    print("sample %s" % record["sample"]["sha256"])
    if problem:
        print("NOT verified: entry %d changed (%s)" % problem)
        return 1
    print("verified: %d entries, every link matches" % count)
    print("head %s" % head)
    print("Tamper-evident, not tamper-proof: compare the head with one kept elsewhere.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
