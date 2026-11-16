#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""The control hover guard (0.9.0 UI round 2, part help).

A control of the desktop app (button, checkbox, radio, combo box, text field,
slider, drag value, selectable label, toggle chip) explains itself on its own
hover, through one helper: `widgets::hover_help(ui, text, add)` /
`widgets::hover_help_or(..)` or the `Tip` methods `.help_tip(text)` /
`.help_tip_or(text, reason)`. The text is for what the control's word cannot
say, and is short: one sentence, two at most (checked here for a string
literal: at most two sentences, no blank line, at most 300 characters; a
computed text is not measured).

This check also reads the non-test Rust code of `monitor-ui` and fails on a
raw hover call (`on_hover_text`, `on_disabled_hover_text`, `on_hover_ui`, ...)
whose receiver is a control unless its text is a string literal of at most
four words and 40 characters (a name).

What may stay raw on a control goes through the other `widgets::Tip` helpers,
which this check accepts by name: `.name_tip(..)` (an icon-only control's
name; a literal there must still be a name), `.value_tip(..)` (a value shown
cut short, whole) and `.reason_tip(..)` (a disabled control's short reason).
A line may also carry the marker `// hover: <why>` (on the call's line or the
line above) for a case none of them fits.

The receiver is the method chain before the call; a bare variable is looked
up in its `let` above. Test code is skipped: `tests/` directories,
`*tests.rs`, `test_*.rs`, `*test_support.rs` and `#[cfg(test)]` items.

Usage: check-control-hover.py [--root DIR] [--list]. Exit 0 when clean;
`--list` prints every hover call on a control with its verdict.
"""
import argparse
import pathlib
import re
import sys

UI_SRC = "src/antinomie/monitor/crates/monitor-ui/src"
NAME_WORDS = 4
NAME_CHARS = 40
HELP_SENTENCES = 2
HELP_CHARS = 300
HELP_CALL = re.compile(r"\bhover_help(?:_or)?\s*\(|\.\s*help_tip(?:_or)?\s*\(")

HOVER = re.compile(
    r"\.\s*(on_hover_text|on_disabled_hover_text|on_hover_ui|on_disabled_hover_ui|"
    r"on_hover_text_at_pointer|on_hover_ui_at_pointer|name_tip)\s*\("
)
CONTROL = re.compile(
    r"\b(button|small_button|checkbox|radio|radio_value|selectable_label|selectable_value|"
    r"toggle_value|text_edit_singleline|text_edit_multiline|menu_button)\s*\(|"
    r"\b(Button|Checkbox|RadioButton|ComboBox|SelectableLabel|TextEdit|Slider|DragValue|"
    r"ImageButton)\s*::|"
    r"\b(toggle_chip|toggle_chip_with|primary_button|danger_button|danger_text_button|"
    r"text_field|single_line)\s*\("
)
MARKER = re.compile(r"//\s*hover:")
TEST_FILE = re.compile(r"(^|/)tests/|(^|/)[^/]*tests\.rs$|(^|/)test_[^/]*\.rs$|test_support\.rs$")
KEYWORDS = {"if", "while", "match", "return", "let", "in", "else", "mut", "move", "for", "break"}


def mask(text):
    """Blank comments and the inside of string and char literals, keeping
    the layout, so brackets and calls in them never count."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text.startswith('r#"', i) or text.startswith('r"', i):
            hashes = 1 if text[i + 1] == "#" else 0
            close = '"' + "#" * hashes
            body = i + 2 + hashes
            j = text.find(close, body)
            j = n if j < 0 else j
            for k in range(body, j):
                if out[k] != "\n":
                    out[k] = "~"
            i = j + len(close)
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = "~"
            i = j + 1
        elif text[i] == "'" and i + 2 < n and (
            text[i + 2] == "'" or (text[i + 1] == "\\" and i + 3 < n and text[i + 3] == "'")
        ):
            end = i + (2 if text[i + 2] == "'" else 3)
            for k in range(i + 1, end):
                out[k] = "~"
            i = end + 1
        else:
            i += 1
    return "".join(out)


def strip_cfg_test(masked):
    """Blank `#[cfg(test)]` items (a module or a function) in masked text."""
    out = list(masked)
    for m in re.finditer(r"#\[cfg\(test\)\]", masked):
        brace = masked.find("{", m.end())
        semi = masked.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        depth, j = 0, brace
        while j < len(masked):
            if masked[j] == "{":
                depth += 1
            elif masked[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        for k in range(m.start(), min(j + 1, len(out))):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def matching_open(s, close):
    depth = 0
    k = close
    while k >= 0:
        if s[k] in ")]}":
            depth += 1
        elif s[k] in "([{":
            depth -= 1
            if depth == 0:
                return k
        k -= 1
    return 0


def chain_start(s, pos):
    """Where the postfix method chain that ends at `pos` starts."""
    i = pos
    while True:
        j = i - 1
        while j >= 0 and s[j].isspace():
            j -= 1
        if j < 0:
            return i
        c = s[j]
        if c in ")]":
            i = matching_open(s, j)
            continue
        if c in ".:!":
            i = j
            continue
        if c.isalnum() or c == "_":
            k = j
            while k >= 0 and (s[k].isalnum() or s[k] == "_"):
                k -= 1
            if s[k + 1 : j + 1] in KEYWORDS:
                return i
            i = k + 1
            m = k
            while m >= 0 and s[m].isspace():
                m -= 1
            if m >= 0 and s[m] in ".:":
                continue
            return i
        return i


def call_end(s, open_pos):
    depth, j = 1, open_pos
    while j < len(s) and depth:
        if s[j] in "([{":
            depth += 1
        elif s[j] in ")]}":
            depth -= 1
        j += 1
    return j


def statement_end(masked, start):
    """Where the statement that starts at `start` ends (its `;`)."""
    end, depth = start, 0
    while end < len(masked):
        c = masked[end]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth <= 0:
            break
        end += 1
    return end


def resolve(masked, name, before):
    """The expression of the nearest `let name = ...;` that ends above
    `before` (a `let name = match .. { .. name.on_hover_text(..) }` is the
    one being built, so the binding before it counts)."""
    found = None
    for m in re.finditer(r"\blet\s+(?:mut\s+)?" + re.escape(name) + r"\s*(?::[^=]+)?=", masked[:before]):
        end = statement_end(masked, m.end())
        if end < before:
            found = (m.end(), end)
    if not found:
        return ""
    return masked[found[0] : found[1]]


def is_name(argument):
    argument = argument.strip()
    if not re.fullmatch(r'"(?:[^"\\]|\\.)*"', argument, re.S):
        return False
    text = re.sub(r"\\\n\s*", " ", argument[1:-1])
    return len(text.split()) <= NAME_WORDS and len(text) <= NAME_CHARS


def split_arguments(masked, raw, open_pos):
    """The raw text of each top-level argument of the call opened at `open_pos`."""
    end = call_end(masked, open_pos) - 1
    parts, depth, begin = [], 0, open_pos
    for j in range(open_pos, end):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(raw[begin:j])
            begin = j + 1
    parts.append(raw[begin:end])
    return [part.strip() for part in parts]


def long_help(argument):
    """Is this string literal more than two sentences, a blank line, or too long?"""
    if not re.fullmatch(r'"(?:[^"\\]|\\.)*"', argument, re.S):
        return False
    text = re.sub(r"\\\n\s*", " ", argument[1:-1])
    if "\\n\\n" in text or "\n\n" in text or len(text) > HELP_CHARS:
        return True
    sentences = re.findall(r"[.!?](?:\s+|$)(?=[A-Z`*(]|$)", text.strip() + " ")
    return len(sentences) > HELP_SENTENCES


def check_help(masked, raw):
    """(line, method, verdict, text) of every help call with a long literal."""
    found = []
    for m in HELP_CALL.finditer(masked):
        arguments = split_arguments(masked, raw, m.end())
        index = 1 if m.group(0).lstrip().startswith("hover_help") else 0
        if index >= len(arguments) or not long_help(arguments[index]):
            continue
        line = raw.count("\n", 0, m.start()) + 1
        found.append((line, m.group(0).strip(" .("), arguments[index]))
    return found


def check_file(path, rel):
    raw = path.read_text(encoding="utf-8")
    masked = strip_cfg_test(mask(raw))
    lines = raw.split("\n")
    verdicts = []
    for line, method, argument in check_help(masked, raw):
        marked = any(
            MARKER.search(lines[index])
            for index in (line - 1, line - 2)
            if 0 <= index < len(lines)
        )
        verdicts.append(
            (rel, line, method, "marked" if marked else "FAIL help text of more than two sentences",
             " ".join(argument.split())[:80])
        )
    for m in HOVER.finditer(masked):
        method = m.group(1)
        line = raw.count("\n", 0, m.start()) + 1
        start = chain_start(masked, m.start())
        receiver = masked[start : m.start()]
        bare = re.fullmatch(r"\s*(\w+)\s*", receiver)
        if bare and bare.group(1) not in ("self",):
            receiver = resolve(masked, bare.group(1), start)
        if method != "name_tip" and not CONTROL.search(receiver):
            continue
        end = call_end(masked, m.end())
        argument = raw[m.end() : end - 1]
        marked = any(
            MARKER.search(lines[index])
            for index in (line - 1, line - 2)
            if 0 <= index < len(lines)
        )
        if marked:
            verdict = "marked"
        elif method.endswith("_ui"):
            verdict = "FAIL hover ui on a control"
        elif is_name(argument):
            verdict = "name"
        elif method == "name_tip" and not argument.strip().startswith('"'):
            verdict = "name"  # checked when it runs (debug builds)
        else:
            verdict = "FAIL long or computed text on a control"
        verdicts.append((rel, line, method, verdict, " ".join(argument.split())[:80]))
    return verdicts


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=pathlib.Path(__file__).resolve().parent.parent)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    source = root / UI_SRC
    if not source.is_dir():
        print(f"no {UI_SRC} under {root}", file=sys.stderr)
        return 2
    verdicts = []
    for path in sorted(source.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if TEST_FILE.search(path.relative_to(source).as_posix()):
            continue
        verdicts.extend(check_file(path, rel))
    failures = [v for v in verdicts if v[3].startswith("FAIL")]
    if args.list:
        for rel, line, method, verdict, argument in verdicts:
            print(f"{verdict:8} {rel}:{line} {method}({argument})")
    for rel, line, method, verdict, argument in failures:
        print(f"{rel}:{line}: {verdict[5:]}: {method}({argument})", file=sys.stderr)
    if failures:
        print(
            f"{len(failures)} hover text(s) on controls: explain through widgets::hover_help "
            f"in one or two sentences, or keep a raw hover to a name of at most {NAME_WORDS} "
            "words (see widgets/help.rs)",
            file=sys.stderr,
        )
        return 1
    print(f"control hover guard: {len(verdicts)} hover call(s) on controls, all names, short help or marked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
