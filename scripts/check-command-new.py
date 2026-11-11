#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""The `Command::new` allow-list gate (design A21, card P5-2).

The service must have no code path that executes a submitted file: the only
programs the host starts are fixed tools, administrator-configured hooks and
the engine's workers. This check lists every place in non-test Rust code of
the monitor workspace that starts a process (`Command::new`, an `exec*` call,
a `Command` import under another name) and compares it with
`scripts/command-new-allowlist.txt`, one line per file:

    <path relative to the repository root> <count> <reason>

A call in a file that is not listed, more calls than listed, or an entry that
lists more than exist (so the list cannot go stale) fails. Test code is not
counted: `tests/` directories, `*tests.rs` / `tests/` modules, `fixtures.rs`,
`testing.rs`, `test_exec.rs`, `examples/` (developer programs that are not shipped),
and `#[cfg(test)]` items.

Usage: check-command-new.py [--root DIR] [--list FILE]. Exit 0 when clean.
"""
import argparse
import pathlib
import re
import sys

# `Command::new` starts a process only where `Command` is std's (or tokio's);
# a file with its own `Command` type and no such import is not counted.
STD_COMMAND = re.compile(r"\bprocess\s*::\s*(?:Command\b|\*|\{[^}]*\b(?:Command|\*)\b[^}]*\})")
NEW = re.compile(r"\bCommand\s*::\s*new\b")
QUALIFIED_NEW = re.compile(r"\bprocess\s*::\s*Command\s*::\s*new\b")
ALIAS = re.compile(r"\bprocess\s*::\s*(?:Command\s+as\b|\{[^}]*\bCommand\s+as\b)")
EXEC = re.compile(
    r"\b(?:libc|unistd|runtime|nix)\s*::\s*(?:\w+\s*::\s*)*(?:exec\w*|fexecve)\s*\("  # exec family
    r"|\.exec\s*\(\s*\)"  # CommandExt::exec()
)
SCAN_DIRS = ["src/antinomie/monitor/crates", "src/antinomie/monitor/fuzz"]
TEST_FILE = re.compile(r"(^|/)(tests|testdata|fixtures|examples)/|(^|/)(test_exec|[^/]*(tests|fixtures|testing))\.rs$")


def strip_comments_and_strings(text):
    """Blank out comments, string and char literals, keeping the layout, so a
    brace or a call in a literal never counts."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif text[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == "r" and re.match(r'r#*"', text[i:]):
            hashes = len(re.match(r"r(#*)", text[i:]).group(1))
            end = '"' + "#" * hashes
            j = text.find(end, i + 2 + hashes)
            j = n if j < 0 else j + len(end)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == "'" and re.match(r"'(\\.[^']*|[^\\'])'", text[i:]):
            j = text.find("'", i + 2 if text[i + 1] == "\\" else i + 2) + 1
            out.append(" " * (j - i))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def drop_cfg_test(code):
    """Blank every `#[cfg(test)]` item (a `mod x;` line or a braced block)."""
    pattern = re.compile(r"#\[cfg\(\s*test\s*\)\]")
    while True:
        m = pattern.search(code)
        if not m:
            return code
        i = m.end()
        # Further attributes between this one and the item.
        while True:
            m2 = re.match(r"\s*#\[[^\]]*\]", code[i:])
            if not m2:
                break
            i += m2.end()
        semi = code.find(";", i)
        brace = code.find("{", i)
        if brace < 0 or (0 <= semi < brace):
            end = (len(code) if semi < 0 else semi + 1)
        else:
            depth, end = 0, brace
            while end < len(code):
                if code[end] == "{":
                    depth += 1
                elif code[end] == "}":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
        code = code[: m.start()] + re.sub(r"[^\n]", " ", code[m.start() : end]) + code[end:]


def count_calls(text):
    code = drop_cfg_test(strip_comments_and_strings(text))
    news = len(QUALIFIED_NEW.findall(code))
    if STD_COMMAND.search(code):
        news = len(NEW.findall(code)) + len(ALIAS.findall(code))
    return news + len(EXEC.findall(code))


def scan(root):
    found = {}
    for sub in SCAN_DIRS:
        for path in sorted((root / sub).rglob("*.rs")):
            rel = path.relative_to(root).as_posix()
            if "/target/" in rel or TEST_FILE.search(rel):
                continue
            n = count_calls(path.read_text(encoding="utf-8", errors="replace"))
            if n:
                found[rel] = n
    return found


def read_list(path):
    allowed = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or not parts[1].isdigit():
            sys.exit(f"{path}:{number}: expected `<path> <count> <reason>`")
        allowed[parts[0]] = int(parts[1])
    return allowed


def check(found, allowed):
    problems = []
    for rel, n in sorted(found.items()):
        if rel not in allowed:
            problems.append(f"{rel}: {n} process start(s) in a file that is not on the allow-list")
        elif n > allowed[rel]:
            problems.append(f"{rel}: {n} process start(s), the allow-list says {allowed[rel]}")
    for rel, n in sorted(allowed.items()):
        have = found.get(rel, 0)
        if have < n:
            problems.append(f"{rel}: the allow-list says {n} but there are {have}; lower or remove the entry")
    return problems


def main():
    here = pathlib.Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=pathlib.Path, default=here.parent)
    ap.add_argument("--list", type=pathlib.Path, default=here / "command-new-allowlist.txt")
    args = ap.parse_args()
    problems = check(scan(args.root), read_list(args.list))
    for p in problems:
        print(f"check-command-new: {p}", file=sys.stderr)
    if problems:
        print(
            "check-command-new: a new process start needs a reviewed entry in scripts/command-new-allowlist.txt "
            "(it must never run a submitted file; see design A21)",
            file=sys.stderr,
        )
        return 1
    print("check-command-new: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
