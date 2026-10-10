#!/usr/bin/env python3
"""Write the Volatility 3 symbol table (ISF) of a kernel build, xz-compressed.

    make-kernel-symbols.py --vmlinux FILE --system-map FILE --output FILE
                           [--tools DIR]

Volatility's dwarf2json reads the types from the kernel's DWARF debug
information and the addresses from System.map. The tool is downloaded once
from its upstream release into --tools (default: work/tools of this kit),
pinned by SHA-256. The table lets Volatility analyse memory dumps of guests
running exactly this kernel.
"""
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

KIT = Path(__file__).resolve().parent.parent
DWARF2JSON = {
    "version": "0.9.0",
    "url": "https://github.com/volatilityfoundation/dwarf2json/releases/download/"
           "v0.9.0/dwarf2json-linux-amd64",
    "sha256": "e2e75ba5bc9c22bc38a48edffbb050456d089d54998d54f46cb580223d9fbc6b",
    "size": 2986584,
}


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dwarf2json(tools):
    """The pinned dwarf2json executable, downloaded on first use."""
    tool = tools / f"dwarf2json-{DWARF2JSON['version']}"
    if tool.is_file() and checksum(tool) == DWARF2JSON["sha256"]:
        return tool
    tools.mkdir(parents=True, exist_ok=True)
    print(f"downloading dwarf2json {DWARF2JSON['version']}", flush=True)
    with tempfile.NamedTemporaryFile(dir=tools, delete=False) as partial:
        with urllib.request.urlopen(DWARF2JSON["url"], timeout=120) as response:
            shutil.copyfileobj(response, partial, 1024 * 1024)
    partial = Path(partial.name)
    if partial.stat().st_size != DWARF2JSON["size"] or checksum(partial) != DWARF2JSON["sha256"]:
        partial.unlink()
        raise RuntimeError("dwarf2json download does not match its pinned SHA-256")
    partial.chmod(0o755)
    os.replace(partial, tool)
    return tool


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vmlinux", type=Path, required=True)
    parser.add_argument("--system-map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tools", type=Path, default=KIT / "work/tools")
    args = parser.parse_args()
    try:
        tool = dwarf2json(args.tools)
        if shutil.which("xz") is None:
            raise RuntimeError("xz is required (xz-utils)")
        partial = args.output.with_name(args.output.name + ".part")
        with partial.open("wb") as output:
            table = subprocess.Popen([tool, "linux", "--elf", args.vmlinux,
                                      "--system-map", args.system_map], stdout=subprocess.PIPE)
            compress = subprocess.run(["xz", "-6", "-T0", "-c"], stdin=table.stdout,
                                      stdout=output, check=False)
            table.stdout.close()
            if table.wait() != 0 or compress.returncode != 0:
                partial.unlink(missing_ok=True)
                raise RuntimeError(f"dwarf2json exited with {table.returncode}, "
                                   f"xz with {compress.returncode}")
        os.replace(partial, args.output)
    except (RuntimeError, OSError) as error:
        print(f"make-kernel-symbols: {error}", file=sys.stderr)
        sys.exit(1)
    print(args.output, flush=True)


if __name__ == "__main__":
    main()
