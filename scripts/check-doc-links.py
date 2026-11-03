#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check every relative link and anchor in docs/ (recursively), README.md,
CHANGELOG.md, CONTRIBUTING.md, AGENTS.md and SECURITY.md.

A link is a missing file, or a `#anchor` that is not a heading of the target
Markdown file (GitHub's slug rules). Links inside code fences and absolute URLs
are skipped. Exit status 1 when anything is reported.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP = ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "AGENTS.md", "SECURITY.md"]


def doc_files():
    found = []
    for base, _dirs, names in os.walk(os.path.join(ROOT, "docs")):
        found += [os.path.join(base, n) for n in names if n.endswith(".md")]
    found.sort()
    return found + [os.path.join(ROOT, n) for n in TOP if os.path.exists(os.path.join(ROOT, n))]


def slug(heading):
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def strip_fences(text):
    return re.sub(r"^```.*?^```", "", text, flags=re.S | re.M)


_anchors = {}


def anchors(path):
    if path not in _anchors:
        found = {}
        with open(path, encoding="utf-8") as handle:
            for line in strip_fences(handle.read()).split("\n"):
                match = re.match(r"#{1,6}\s+(.*)", line)
                if match:
                    base = slug(match.group(1))
                    count = found.get(base, 0)
                    found[base] = count + 1
                    if count:
                        found[f"{base}-{count}"] = 1
        _anchors[path] = set(found)
    return _anchors[path]


def main():
    problems = 0
    files = doc_files()
    for path in files:
        with open(path, encoding="utf-8") as handle:
            text = strip_fences(handle.read())
        shown = os.path.relpath(path, ROOT)
        for match in re.finditer(r"\]\(([^)\s]+)\)", text):
            target = match.group(1)
            if target.startswith(("http:", "https:", "mailto:")):
                continue
            part, _, fragment = target.partition("#")
            dest = os.path.normpath(os.path.join(os.path.dirname(path), part)) if part else path
            if not os.path.exists(dest):
                print(f"MISSING {shown}: {target}")
                problems += 1
            elif fragment and dest.endswith(".md") and fragment not in anchors(dest):
                print(f"ANCHOR  {shown}: {target}")
                problems += 1
    print(f"links checked in {len(files)} files; problems: {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
