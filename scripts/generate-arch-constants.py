#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Generate an architecture's constants file from the pinned Linux 6.12.94 UAPI.

The host's decoding tables (flag groups, selector names, socket options, errno
and signal names) carry x86-64 values. For another architecture this file lists
where its value of a named constant differs from x86-64's (`changed`), which
names x86-64 defines and it lacks (`absent`), and the arch-only names a group
gains (`additions`), together with the data model and identity the host decodes
by. x86-64's own file is empty in those three parts by construction.

Every name is evaluated by libclang over the installed-UAPI view of the pinned
tree for the arch's target, one UAPI header at a time, so a value is the one a
program built for that arch sees. Names no UAPI header defines (kernel-internal
values, descriptive labels) are not evaluated and keep their generic value.

Development prerequisite: the libclang Python binding (as for the layouts).
"""
import argparse
import hashlib
import importlib.util
import json
import re
import tempfile
from pathlib import Path

from clang import cindex

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / "src/antinomie/monitor"
KERNEL = ROOT / "work/debian-6.12.94-1-trixie/core"
_spec = importlib.util.spec_from_file_location("layouts", ROOT / "scripts/generate-filter-layouts.py")
layouts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(layouts)

# Host sources whose string literals name the constants they decode.
SOURCES = ["crates/monitor-core/src/syscalls.rs", "crates/monitor-core/src/syscalls/selectors.rs",
           "crates/monitor-core/src/syscalls/socket_options.rs", "crates/monitor-ui/src/values.rs",
           "crates/monitor-core/src/typed_fields/signals.rs"]
NAME = re.compile(r'"([A-Z][A-Z0-9_]{2,})"')
# Identity and data model per architecture (ELF e_machine, audit AUDIT_ARCH_*),
# and arch-only names a host group gains, by the group's name in the host.
IDENTITY = {
    "x86_64": {"elf_machine": 62, "elf_class": 64, "endianness": "little", "data_model": "LP64",
               "audit_arch": "c000003e", "additions": {}},
    "aarch64": {"elf_machine": 183, "elf_class": 64, "endianness": "little", "data_model": "LP64",
                "audit_arch": "c00000b7",
                "additions": {"protection": ["PROT_BTI", "PROT_MTE"],
                              "ptrace_request": ["PTRACE_PEEKMTETAGS", "PTRACE_POKEMTETAGS"]}},
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_names():
    names = set()
    for relative in SOURCES:
        names.update(NAME.findall((MONITOR / relative).read_text()))
    return sorted(names)


def evaluate(kernel, arch, names):
    """Each name's value for ARCH, from the first UAPI header that defines it."""
    spec = layouts.ARCHES[arch]
    schema = json.loads((MONITOR / "protocol" / arch / "native-syscalls.json").read_text())
    values, conflicts = {}, set()
    with tempfile.TemporaryDirectory(prefix="ant-constants-") as temporary:
        overlay = Path(temporary)
        layouts.uapi_overlay(kernel, spec, schema, overlay, {})
        args = layouts.compiler_args(kernel, spec, overlay) + ["-ferror-limit=0", "-w"]
        headers = sorted({f"linux/{p.relative_to(kernel / 'include/uapi/linux')}"
                          for p in (kernel / "include/uapi/linux").glob("*.h")}
                         | {f"asm/{p.name}" for p in (kernel / spec["uapi"] / "asm").glob("*.h")}
                         | {f"asm/{p.name}" for p in (kernel / "include/uapi/asm-generic").glob("*.h")})
        index = cindex.Index.create()
        for header in headers:
            prelude = f"#include <linux/types.h>\n#include <{header}>\n"
            lines = {i: name for i, name in enumerate(names)}
            for _ in range(3):
                code = prelude + "".join(f"enum {{ __ant_c_{i} = ({name}) }};\n" for i, name in lines.items())
                unit = index.parse("constants.c", args=args, unsaved_files=[("constants.c", code)])
                if any(d.severity >= cindex.Diagnostic.Error and d.location.file
                       and d.location.file.name != "constants.c" for d in unit.diagnostics):
                    lines = {}
                    break
                order = list(lines)
                bad = {order[d.location.line - 3] for d in unit.diagnostics
                       if d.severity >= cindex.Diagnostic.Error and d.location.file
                       and d.location.file.name == "constants.c" and 3 <= d.location.line < 3 + len(order)}
                if not bad:
                    break
                lines = {i: name for i, name in lines.items() if i not in bad}
            else:
                lines = {}
            if not lines:
                continue
            for cursor in unit.cursor.walk_preorder():
                if cursor.kind == cindex.CursorKind.ENUM_CONSTANT_DECL and cursor.spelling.startswith("__ant_c_"):
                    name = lines.get(int(cursor.spelling.removeprefix("__ant_c_")))
                    if name is None:
                        continue
                    value = cursor.enum_value
                    if name in values and values[name] != value:
                        conflicts.add(name)
                    values.setdefault(name, value)
    return values, conflicts


def generate(kernel, arch):
    names = host_names()
    for extra in IDENTITY[arch]["additions"].values():
        names = sorted(set(names) | set(extra))
    base, base_conflicts = evaluate(kernel, "x86_64", names)
    values, conflicts = (base, base_conflicts) if arch == "x86_64" else evaluate(kernel, arch, names)
    if conflicts - base_conflicts:
        raise ValueError(f"{arch}: names with different values in two UAPI headers: {sorted(conflicts)}")
    additions = {}
    for group, extra in IDENTITY[arch]["additions"].items():
        missing = [name for name in extra if name not in values]
        if missing:
            raise ValueError(f"{arch}: additions not defined by the pinned UAPI: {missing}")
        additions[group] = {name: values[name] for name in extra}
    added = {name for extra in IDENTITY[arch]["additions"].values() for name in extra}
    identity = {key: value for key, value in IDENTITY[arch].items() if key != "additions"}
    spec = layouts.ARCHES[arch]
    return {
        "format_version": 1, "kernel_version": "6.12.94", "architecture": arch, **identity,
        "layout_prefix": spec["prefix"],
        "changed": {name: values[name] for name in sorted(base)
                    if name in values and values[name] != base[name] and name not in base_conflicts},
        "absent": sorted(name for name in base if name not in values and name not in added),
        "additions": additions,
        "provenance": {"generator": "scripts/generate-arch-constants.py",
                       "compiler_target": spec["target"], "uapi": [spec["uapi"], "include/uapi"],
                       "makefile_sha256": sha(kernel / "Makefile"),
                       "evaluated_names": len(values),
                       "method": "libclang enum evaluation over the pinned installed-UAPI view, one header per unit; "
                                 "names compared with x86-64's evaluation of the same names"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=KERNEL)
    parser.add_argument("--arch", choices=sorted(IDENTITY), default="x86_64")
    parser.add_argument("--output", type=Path, help="default: protocol/<arch>/constants.json")
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    output = options.output or MONITOR / "protocol" / options.arch / "constants.json"
    generated = json.dumps(generate(options.kernel.resolve(), options.arch), indent=2) + "\n"
    if options.check:
        if output.read_text() != generated:
            raise SystemExit(f"{output} differs from the pinned UAPI; regenerate and review")
        print("constants match the pinned UAPI")
    else:
        output.write_text(generated)
        print("wrote", output)


if __name__ == "__main__":
    main()
