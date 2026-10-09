#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the bundled community YARA rule file from a YARA-Forge package.

usage: refresh-yara-rules.py YARA_FORGE_RULES.yar RELEASE OUTPUT.yar [EXCLUDE ...]

Keeps only rules whose `license` meta names a license that allows
redistribution (see ALLOWED); every kept rule retains its author, license and
source_url meta for attribution. EXCLUDE names rules to drop, for example the
ones `cargo run --example rules-check` reports as not compiling with YARA-X.
"""
import re
import sys

ALLOWED = (
    "CC BY-SA 4.0",
    "CC BY 4.0",
    "Detection Rule License 1.1",
    "DRL-1.1",
    "BSD 2-Clause",
    "Apache License 2.0",
    "This Yara rule is provided under the Apache License 2.0",
    "MIT",
)
START = re.compile(r"^(?:(?:private|global)\s+)*rule\s+(\w+)")


def blocks(lines):
    """Yield (name, lines) of each top-level rule; YARA-Forge closes every
    rule with a lone '}' in column 0."""
    current, name = None, None
    for line in lines:
        match = START.match(line)
        if current is None and match:
            current, name = [line], match.group(1)
            continue
        if current is not None:
            current.append(line)
            if line.rstrip("\n") == "}":
                yield name, current
                current = None


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    source, release, output = sys.argv[1:4]
    exclude = set(sys.argv[4:])
    with open(source, encoding="utf-8") as handle:
        lines = handle.readlines()
    imports = sorted({l.strip() for l in lines if l.startswith("import ")})
    kept, skipped = [], 0
    for name, block in blocks(lines):
        text = "".join(block)
        license = re.search(r'^\s*(?:malpedia_)?license = "([^"]*)"', text, re.M)
        if name in exclude or not license or not license.group(1).startswith(ALLOWED):
            skipped += 1
            continue
        kept.append(text)
    with open(output, "w", encoding="utf-8") as out:
        out.write(
            "/*\n"
            f" * Community YARA rules from YARA-Forge release {release} (core package),\n"
            " * https://github.com/YARAHQ/yara-forge, reduced by Antinomie's\n"
            " * scripts/refresh-yara-rules.py to rules whose license meta allows\n"
            " * redistribution: " + ", ".join(ALLOWED[:6]) + ".\n"
            " * Each rule keeps its author, license and source_url meta; the license\n"
            " * texts are in LICENSES/third-party/rules/. This file is not covered by\n"
            " * Antinomie's MIT license.\n"
            f" * Rules: {len(kept)} kept, {skipped} not redistributable or not\n"
            " * compiling with YARA-X.\n"
            " */\n\n"
        )
        out.write("\n".join(imports) + "\n\n")
        out.write("\n".join(kept))
    print(f"kept {len(kept)}, skipped {skipped}")


if __name__ == "__main__":
    main()
