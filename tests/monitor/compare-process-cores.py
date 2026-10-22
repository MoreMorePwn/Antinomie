#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Compare real acquisition evidence against GDB, without executing the fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def file_evidence(path):
    digest = hashlib.sha256()
    marker = b"Antinomie process core evidence before exit"
    previous = b""
    found = False
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            combined = previous + chunk
            found |= marker in combined
            previous = combined[-len(marker):]
    return digest.hexdigest(), found


def compare(case, executable):
    core = Path(case["core"]).resolve(strict=True)
    metadata = json.loads((core.parent / "core.json").read_text())
    expected = {thread["tid"]: dict(thread["registers"]) for thread in case["threads"]}
    names = sorted({name for registers in expected.values() for name in registers})
    with tempfile.TemporaryDirectory(prefix="ant-core-gdb-") as temporary:
        temporary = Path(temporary)
        output = temporary / "registers.json"
        script = temporary / "compare.py"
        script.write_text(
            "import gdb, json\n"
            f"names = {names!r}\n"
            "rows = {}\n"
            "for thread in gdb.selected_inferior().threads():\n"
            "    thread.switch()\n"
            "    tid = thread.ptid[1] or thread.ptid[2] or thread.ptid[0]\n"
            "    registers = {}\n"
            "    for name in names:\n"
            "        try:\n"
            "            alias = 'eflags' if name == 'rflags' else name\n"
            "            registers[name] = int(gdb.parse_and_eval('$' + alias)) & ((1 << 64) - 1)\n"
            "        except (gdb.error, ValueError, TypeError):\n"
            "            pass\n"
            "    rows[str(tid)] = registers\n"
            f"with open({str(output)!r}, 'w') as result:\n"
            "    json.dump(rows, result)\n"
        )
        result = subprocess.run(
            ["gdb", "-nx", "-nh", "-batch", "-iex", "set auto-load off",
             str(executable), str(core), "-ex", f"source {script}"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if result.returncode or not output.exists():
            raise RuntimeError(f"{case['mode']}: GDB failed: {result.stderr}")
        actual = {int(tid): registers for tid, registers in json.loads(output.read_text()).items()}
    # libthread_db can reconstruct a dead leader from libc's thread list even
    # though its PRSTATUS/registers are absent. Accept only registerless extra
    # threads in an explicitly marked coverage-gap core; compare every retained
    # register context strictly.
    unavailable = sorted(actual.keys() - expected.keys())
    coverage_gap = metadata.get("guest_status", {}).get("flags", 0) & 8
    if (expected.keys() - actual.keys()
            or (unavailable and (not coverage_gap or any(actual[tid] for tid in unavailable)))):
        raise RuntimeError(f"{case['mode']}: GDB thread identities differ: {actual.keys()} != {expected.keys()}")
    compared = 0
    for tid, registers in expected.items():
        if not {"rip", "rsp"} <= actual[tid].keys():
            raise RuntimeError(f"{case['mode']}: GDB has no RIP/RSP for thread {tid}")
        for name, value in actual[tid].items():
            if value != registers[name]:
                raise RuntimeError(f"{case['mode']}: thread {tid} {name}: GDB={value:x}, parser={registers[name]:x}")
            compared += 1
    digest, found = file_evidence(core)
    if digest != metadata["sha256"] or core.stat().st_size != metadata["stored_size"]:
        raise RuntimeError(f"{case['mode']}: durable extent or SHA-256 differs from the retained file")
    if case["mode"] != "large" and not found:
        raise RuntimeError(f"{case['mode']}: dirty-page fixture evidence was not retained")
    return {"mode": case["mode"], "threads": len(expected),
            "registers_compared": compared, "sha256": digest,
            "dirty_page_evidence": found, "state": metadata["state"],
            "unavailable_gdb_thread_ids": unavailable}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("executable", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    results = json.loads(args.results.read_text())
    if not results:
        raise RuntimeError("no real acquisition evidence to compare")
    comparisons = [compare(case, args.executable.resolve(strict=True)) for case in results]
    args.output.write_text(json.dumps(comparisons, indent=2) + "\n")
    for result in comparisons:
        print(f"PASS {result['mode']}: {result['threads']} GDB threads, "
              f"{result['registers_compared']} matching registers and retained file hash")


if __name__ == "__main__":
    main()
