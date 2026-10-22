#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep the Quilt view of the guest patch series in step with the series itself.

usage: sync-quilt-view.py [--check]

The guest series lives as mail-format patches in src/antinomie/core/6.12
(`scripts/commit.sh` exports them). The Debian packaging workflow applies the
Quilt view in src/antinomie/patches/debian-6.12.94-1-trixie/antinomie: the same
diffs under a DEP-3 header, listed in `series`. commit.sh writes both, but a
patch added any other way leaves the view behind; this adds the missing view
patches and series lines, and never rewrites one that exists.

--check changes nothing: it exits 1 if the view lacks a patch of the series, if
`series` is not exactly the view's patches in order, or if a view patch carries
a different diff from the series patch of its number.
"""
import email.utils
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "src/antinomie/core/6.12"
VIEW = ROOT / "src/antinomie/patches/debian-6.12.94-1-trixie/antinomie"
NUMBER = re.compile(r"^(\d{4})-")


def parse(path):
    """(subject, author, date, body paragraphs, diff) of a mail-format patch."""
    text = path.read_text(encoding="utf-8")
    head, _, rest = text.partition("\n\n")
    subject = re.sub(r"\s*\n\s*", " ", head.split("Subject: ", 1)[1].split("\nDate:")[0])
    subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", subject)
    author = re.search(r"^From: (.*)$", head, re.M).group(1)
    date = email.utils.parsedate_to_datetime(re.search(r"^Date: (.*)$", head, re.M).group(1)).date()
    # A patch with no message body goes straight from the headers to "---".
    body, _, rest = ("\n" + rest).partition("\n---\n")
    paragraphs = [re.sub(r"\s*\n\s*", " ", p.strip()) for p in body.strip().split("\n\n") if p.strip()]
    diff = rest[rest.index("diff --git"):]
    # format-patch ends with a signature (`-- ` and a version) that git show omits.
    diff = re.sub(r"\n-- \n[^\n]*\n\s*$", "\n", diff)
    return subject, author, date.isoformat(), paragraphs, diff


def changes(diff):
    """The diff without what an export may differ in: blob ids and the function
    names git prints after a hunk's line numbers."""
    lines = (line for line in diff.splitlines() if not line.startswith("index "))
    return [re.sub(r"^(@@ [^@]*@@).*$", r"\1", line) for line in lines]


def view_name(number, subject):
    slug = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-")
    slug = slug.removeprefix("antinomie-")
    return f"{number}-antinomie-{slug}.patch"


def view_text(path):
    subject, author, date, paragraphs, diff = parse(path)
    text = (f"Description: {subject}\nAuthor: {author}\nOrigin: project\nForwarded: no\n"
            f"Last-Update: {date}\n\n")
    if paragraphs:
        text += "  ".join(paragraphs) + "\n"
    return view_name(path.name[:4], subject), text + "\n---\n" + diff


def main(argv):
    check = "--check" in argv
    by_number = {m.group(1): p for p in sorted(VIEW.glob("*.patch")) if (m := NUMBER.match(p.name))}
    problems, added = [], []
    for core in sorted(CORE.glob("*.patch")):
        number = core.name[:4]
        name, text = view_text(core)
        have = by_number.get(number)
        if have is None:
            problems.append(f"the view has no patch {number}")
            if not check:
                (VIEW / name).write_text(text, encoding="utf-8")
                by_number[number] = VIEW / name
                added.append(name)
        elif changes(have.read_text(encoding="utf-8").partition("\n---\n")[2]) != changes(
            text.partition("\n---\n")[2]
        ):
            problems.append(f"{have.name} differs from the series patch {core.name}")
    names = [by_number[n].name for n in sorted(by_number)]
    series = VIEW / "series"
    listed = series.read_text(encoding="utf-8").split() if series.is_file() else []
    if listed != names:
        problems.append("series does not list the view's patches in order")
        if not check:
            series.write_text("".join(f"{name}\n" for name in names), encoding="utf-8")
    if check:
        for problem in problems:
            print(f"sync-quilt-view: {problem}", file=sys.stderr)
        return 1 if problems else 0
    for name in added:
        print(f"added {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
