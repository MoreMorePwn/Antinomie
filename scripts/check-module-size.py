#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep host Rust modules small enough to read.

Counts the lines of each monitor source file before its test module; test
files (`tests.rs`, `*_tests.rs` and files under a `tests/` directory) are not
counted. A file over LIMIT fails unless it is listed in the allowlist, and a
listed file fails when it grows past its recorded size. Shrinking a listed
file is always allowed; `--update` lowers the recorded sizes to the current
ones and drops files that are now under the limit. It never raises a size.

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
TEST_MODULE = re.compile(r"^#\[cfg\(test\)\]\s*\n(?:pub(?:\([a-z]+\))? )?mod \w*tests?\b", re.M)


def is_test_file(path):
    return path.name == "tests.rs" or path.name.endswith("_tests.rs") or "tests" in path.parts[len(CRATES.parts):]


def code_lines(path):
    text = path.read_text()
    match = TEST_MODULE.search(text)
    if match:
        text = text[: match.start()]
    return text.count("\n")


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
    for failure in failures:
        print(failure)
    if failures:
        print("Split the file by responsibility; see the module guidance in CONTRIBUTING.md.")
        sys.exit(1)
    listed = sum(1 for name in allowed if name in sizes)
    print(f"module sizes ok: {len(sizes)} files, {listed} allowlisted over {LIMIT} lines")


if __name__ == "__main__":
    main()
