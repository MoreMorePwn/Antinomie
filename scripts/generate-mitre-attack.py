#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Write the bundled ATT&CK technique-name table from the enterprise STIX bundle.

Usage: generate-mitre-attack.py enterprise-attack.json OUTPUT.tsv

The STIX bundle is published at
https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json).
Only technique and sub-technique ids, names and tactics (the kill-chain phase
short names, in kill-chain order) are kept; revoked and deprecated entries are
dropped. See THIRD-PARTY-NOTICES.md for the licence.
"""
import json
import re
import sys


KILL_CHAIN = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def main(source, target):
    with open(source, encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]
    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"),
        "unknown",
    )
    # Kill-chain order of the v20 tactics (Defense Evasion became Stealth plus
    # Defense Impairment); the bundle lists them alphabetically by id.
    order = {name: index for index, name in enumerate(KILL_CHAIN)}
    rows = {}
    for item in objects:
        if item["type"] != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        for reference in item.get("external_references", []):
            identifier = reference.get("external_id", "")
            if reference.get("source_name") == "mitre-attack" and re.fullmatch(r"T\d{4}(\.\d{3})?", identifier):
                name = item["name"].replace("\t", " ").replace("\n", " ").strip()
                phases = sorted(
                    {
                        p["phase_name"]
                        for p in item.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"
                    },
                    key=lambda phase: order.get(phase, 99),
                )
                rows[identifier] = (name, ",".join(phases))
    with open(target, "w", encoding="utf-8", newline="\n") as out:
        out.write(f"# MITRE ATT&CK Enterprise v{version}: technique id, name, tactics.\n")
        out.write("# Copyright The MITRE Corporation; see THIRD-PARTY-NOTICES.md.\n")
        for identifier in sorted(rows):
            name, tactics = rows[identifier]
            out.write(f"{identifier}\t{name}\t{tactics}\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
