#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Keep host Rust modules small enough to read.

Counts the lines of each monitor source file before its test module; test
files (`tests.rs`, `*_tests.rs` and files under a `tests/` directory) are not
counted. A file over LIMIT fails unless it is listed in the allowlist, and a
listed file fails when it grows past its recorded size. Shrinking a listed
file is always allowed; `--update` lowers the recorded sizes to the current
ones and drops files that are now under the limit. It never raises a size.

It also prints a WARNING list of functions longer than FUNCTION_WARN lines
(test code excluded). That list never changes the exit code.

usage: check-module-size.py [--update]
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "src/antinomie/monitor/crates"
ALLOWLIST = Path(__file__).resolve().parent / "module-size-allowlist.txt"
# Lines of non-test code in one file.
LIMIT = 1200
# Lines of one function body above which the report names it. Advisory only.
FUNCTION_WARN = 300
TEST_MODULE = re.compile(r"^#\[cfg\(test\)\]\s*\n(?:pub(?:\([a-z]+\))? )?mod \w*tests?\b", re.M)


def is_test_file(path):
    return path.name == "tests.rs" or path.name.endswith("_tests.rs") or "tests" in path.parts[len(CRATES.parts):]


def code_lines(path):
    text = path.read_text()
    match = TEST_MODULE.search(text)
    if match:
        text = text[: match.start()]
    return text.count("\n")


def function_spans(text):
    """Yields (name, first line, line count) of each `fn` with a body.

    A small scanner, not a parser: it skips comments, strings, raw strings and
    character literals so braces inside them do not count, and it follows
    nested functions and closures as part of the enclosing body.
    """
    n = len(text)
    i = 0
    line = 1
    depth = 0
    # (name, first line, depth at which its body opened)
    open_fns = []
    pending = None  # (name, first line, paren depth) waiting for its body
    parens = 0
    spans = []
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            level = 1
            i += 2
            while i < n and level:
                if text.startswith("/*", i):
                    level += 1
                    i += 2
                elif text.startswith("*/", i):
                    level -= 1
                    i += 2
                else:
                    line += text[i] == "\n"
                    i += 1
        elif (m := re.compile(r'b?r(#*)"').match(text, i)) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            end = '"' + m.group(1)
            j = text.find(end, m.end())
            j = n if j < 0 else j + len(end)
            line += text.count("\n", i, j)
            i = j
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                line += text[i] == "\n"
                i += 1
            i += 1
        elif c == "'":
            m = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'])'").match(text, i)
            i = m.end() if m else i + 1
        elif c.isalpha() or c == "_":
            m = re.compile(r"[A-Za-z0-9_]+").match(text, i)
            word = m.group()
            i = m.end()
            if word == "fn":
                name = re.compile(r"\s+([A-Za-z0-9_]+)").match(text, i)
                if name:
                    pending = (name.group(1), line, parens)
                    parens = 0
                    i = name.end()
        else:
            if c in "([":
                parens += 1
            elif c in ")]":
                parens -= 1
            elif c == ";" and pending and parens == 0:
                pending = None
            elif c == "{":
                depth += 1
                if pending and parens == 0:
                    open_fns.append((pending[0], pending[1], depth))
                    pending = None
            elif c == "}":
                if open_fns and open_fns[-1][2] == depth:
                    name, first, _ = open_fns.pop()
                    spans.append((name, first, line - first + 1))
                depth -= 1
            i += 1
    return spans


def long_functions():
    found = []
    for path in sorted(CRATES.glob("*/src/**/*.rs")):
        if is_test_file(path):
            continue
        text = path.read_text()
        match = TEST_MODULE.search(text)
        if match:
            text = text[: match.start()]
        for name, first, length in function_spans(text):
            if length > FUNCTION_WARN:
                found.append((length, str(path.relative_to(ROOT)), first, name))
    return sorted(found, reverse=True)


def measure():
    sizes = {}
    for path in sorted(CRATES.glob("*/src/**/*.rs")):
        if is_test_file(path):
            continue
        sizes[str(path.relative_to(ROOT))] = code_lines(path)
    return sizes


def load_allowlist():
    allowed = {}
    if ALLOWLIST.is_file():
        for line in ALLOWLIST.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                name, size = line.rsplit(maxsplit=1)
                allowed[name] = int(size)
    return allowed


def main():
    sizes = measure()
    allowed = load_allowlist()
    if sys.argv[1:] == ["--update"]:
        kept = {
            name: min(size, sizes[name])
            for name, size in allowed.items()
            if name in sizes and sizes[name] > LIMIT
        }
        header = (
            "# Files over the module size limit, with the most lines of non-test code\n"
            "# each may have. Split a file to remove it; never raise a number.\n"
        )
        ALLOWLIST.write_text(header + "".join(f"{name} {size}\n" for name, size in sorted(kept.items())))
        print(f"{len(kept)} files remain over {LIMIT} lines")
        return
    failures = []
    for name, size in sizes.items():
        ceiling = allowed.get(name, LIMIT)
        if size > ceiling:
            reason = "grew past its allowlisted size" if name in allowed else f"is over {LIMIT} lines"
            failures.append(f"{name}: {size} lines of non-test code {reason} ({ceiling})")
    long = long_functions()
    if long:
        print(f"WARNING: {len(long)} functions over {FUNCTION_WARN} lines (advisory, not a failure):")
        for length, name, first, function in long:
            print(f"  {length:5} {name}:{first} {function}")
    for failure in failures:
        print(failure)
    if failures:
        print("Split the file by responsibility; see the module guidance in CONTRIBUTING.md.")
        sys.exit(1)
    listed = sum(1 for name in allowed if name in sizes)
    print(f"module sizes ok: {len(sizes)} files, {listed} allowlisted over {LIMIT} lines")


if __name__ == "__main__":
    main()
