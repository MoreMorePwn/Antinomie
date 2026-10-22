#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Write the bundled ATT&CK technique-name table from the enterprise STIX bundle.

Usage: generate-mitre-attack.py enterprise-attack.json OUTPUT.tsv

The STIX bundle is published at
https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json).
Only technique and sub-technique ids and names are kept; revoked and
deprecated entries are dropped. See THIRD-PARTY-NOTICES.md for the licence.
"""
import json
import re
import sys


def main(source, target):
    with open(source, encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]
    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"),
        "unknown",
    )
    rows = {}
    for item in objects:
        if item["type"] != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        for reference in item.get("external_references", []):
            identifier = reference.get("external_id", "")
            if reference.get("source_name") == "mitre-attack" and re.fullmatch(r"T\d{4}(\.\d{3})?", identifier):
                name = item["name"].replace("\t", " ").replace("\n", " ").strip()
                rows[identifier] = name
    with open(target, "w", encoding="utf-8", newline="\n") as out:
        out.write(f"# MITRE ATT&CK Enterprise v{version}: technique id, tab, name.\n")
        out.write("# Copyright The MITRE Corporation; see THIRD-PARTY-NOTICES.md.\n")
        for identifier in sorted(rows):
            out.write(f"{identifier}\t{rows[identifier]}\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
