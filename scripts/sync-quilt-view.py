#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Regenerate the Quilt view of the guest patch series from the series itself.

usage: sync-quilt-view.py [--check]

The guest series lives as mail-format patches in src/antinomie/core/6.12. That
copy is canonical: the kernel build applies it, its SHA-256 is the kernel's
series identity, and the app embeds it in its base build kit. The Debian
packaging workflow applies the Quilt view in
src/antinomie/patches/debian-6.12.94-1-trixie/antinomie instead: the same diffs
under a DEP-3 header, listed in `series`. The view is derived; never edit it.

Without arguments this rewrites the view from the series: one view patch per
series patch, whose header is the patch's commit message (the subject as
Description, the body as its long description) and whose diff is the series
patch's diff; view patches no series patch has are removed, and `series` lists
the view's patches in order. Comment lines in `series` (the section headings)
are kept above the patch they preceded, matched by number.

--check changes nothing: it exits 1 if a view patch is missing, left over, or
not exactly what the series patch of its number produces, or if `series` does
not list the view's patches in order.
"""
import email.utils
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "src/antinomie/core/6.12"
VIEW = ROOT / "src/antinomie/patches/debian-6.12.94-1-trixie/antinomie"
NUMBER = re.compile(r"^(\d{4})-")
# DEP-3 fields a commit message may set in its last paragraph (a backport's
# Origin, say); the others are fixed for the project's own patches.
FIELDS = re.compile(r"^(Origin|Forwarded|Bug(-[A-Za-z]+)?|Applied-Upstream): \S")


def parse(path):
    """(subject, author, date, body lines, diff) of a mail-format patch."""
    text = path.read_text(encoding="utf-8")
    head, _, rest = text.partition("\n\n")
    subject = re.sub(r"\s*\n\s*", " ", head.split("Subject: ", 1)[1].split("\nDate:")[0])
    subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", subject)
    author = re.search(r"^From: (.*)$", head, re.M).group(1)
    date = email.utils.parsedate_to_datetime(re.search(r"^Date: (.*)$", head, re.M).group(1)).date()
    # A patch with no message body goes straight from the headers to "---".
    body, _, rest = ("\n" + rest).partition("\n---\n")
    diff = rest[rest.index("diff --git"):]
    # format-patch ends with a signature (`-- ` and a version) that git show omits.
    diff = re.sub(r"\n-- \n[^\n]*\n\s*$", "\n", diff)
    return subject, author, date.isoformat(), body.strip("\n").splitlines(), diff


def view_name(number, subject):
    slug = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-")
    slug = slug.removeprefix("antinomie-")
    return f"{number}-antinomie-{slug}.patch"


def view_text(path):
    """(name, text) of the view patch for the series patch at path.

    DEP-3: the subject is the Description, and the body its long description in
    the multi-line field form (each line indented one space, an empty line as
    " ."). A last paragraph of Origin:, Forwarded:, Bug: or Applied-Upstream:
    lines sets those fields instead; Origin defaults to project, Forwarded to no.
    """
    subject, author, date, body, diff = parse(path)
    fields = {"Origin": "project", "Forwarded": "no"}
    last = len(body) - next((i for i, line in enumerate(reversed(body)) if not line.strip()), len(body))
    if body[last:] and all(FIELDS.match(line) for line in body[last:]):
        fields.update(line.split(": ", 1) for line in body[last:])
        body = body[:last]
        while body and not body[-1].strip():
            body.pop()
    long_description = "".join(f" {line.rstrip()}\n" if line.strip() else " .\n" for line in body)
    origin = "".join(f"{key}: {value}\n" for key, value in fields.items())
    text = f"Description: {subject}\n{long_description}Author: {author}\n{origin}Last-Update: {date}\n"
    return view_name(path.name[:4], subject), text + "\n---\n" + diff


def series_comments(path):
    """{patch number: comment lines above it}; key None holds trailing comments."""
    comments, pending = {}, []
    if not path.is_file():
        return comments
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            pending.append(line)
        elif m := NUMBER.match(line.strip()):
            if pending:
                comments[m.group(1)] = pending
            pending = []
    if pending:
        comments[None] = pending
    return comments


def series_text(names, comments):
    """`series` listing names in order, with the kept comments.

    A comment whose patch number is gone moves down to the next patch."""
    numbers = [name[:4] for name in names]
    above = {number: [] for number in numbers}
    trailing = []
    for key in sorted(key for key in comments if key is not None):
        target = next((number for number in numbers if number >= key), None)
        (above[target] if target else trailing).extend(comments[key])
    trailing += comments.get(None, [])
    lines = []
    for name, number in zip(names, numbers):
        lines += above[number] + [name]
    lines += trailing
    while lines and not lines[-1].strip():
        lines.pop()
    return "".join(f"{line}\n" for line in lines)


def listed(path):
    """The patch names `series` lists, without its comments."""
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


def main(argv):
    check = "--check" in argv
    expected = dict(view_text(core) for core in sorted(CORE.glob("*.patch")))
    present = {p.name: p for p in sorted(VIEW.glob("*.patch")) if NUMBER.match(p.name)}
    problems = []
    for name, text in expected.items():
        have = present.get(name)
        if have is None:
            problems.append(f"the view has no {name}")
        elif have.read_text(encoding="utf-8") != text:
            problems.append(f"{name} is not what series patch {name[:4]} produces")
        if not check and (have is None or have.read_text(encoding="utf-8") != text):
            VIEW.mkdir(parents=True, exist_ok=True)
            (VIEW / name).write_text(text, encoding="utf-8")
    for name, path in present.items():
        if name not in expected:
            problems.append(f"{name} has no series patch")
            if not check:
                path.unlink()
    series = VIEW / "series"
    names = sorted(expected)
    if listed(series) != names:
        problems.append("series does not list the view's patches in order")
    if not check:
        text = series_text(names, series_comments(series))
        if not series.is_file() or series.read_text(encoding="utf-8") != text:
            series.write_text(text, encoding="utf-8")
    if check:
        for problem in problems:
            print(f"sync-quilt-view: {problem}", file=sys.stderr)
        return 1 if problems else 0
    for problem in problems:
        print(f"fixed: {problem}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
