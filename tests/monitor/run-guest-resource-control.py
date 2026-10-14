#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Test collector Upload/Exec/Input/Read/Signal against an unchanged base.

Uses four-vCPU TCG, shared temporary RAM and a disposable disk snapshot.
There is no QMP socket, host network or write to the base disk.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_directory", type=Path)
    args = parser.parse_args()
    base = args.base_directory.resolve()
    for name in ("kernel", "base.qcow2", "initrd.gz"):
        if not (base / name).is_file():
            parser.error(f"base lacks {name}")
    with tempfile.TemporaryDirectory(prefix="antinomie-resource-control-") as directory:
        work = Path(directory)
        subprocess.run([os.environ.get("CC", "cc"), "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(ROOT / "src/antinomie/transport"),
                        "-I" + str(ROOT / "src/antinomie/monitor/protocol"),
                        str(ROOT / "tests/monitor/guest-resource-control.c"),
                        str(ROOT / "src/antinomie/transport/host.c"),
                        "-o", str(work / "control")], check=True)
        subprocess.run([os.environ.get("ANTINOMIE_GUEST_CC", "musl-gcc"), "-static", "-Os", "-s",
                        "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "src/antinomie/monitor/crates/monitor-core/src/guest_resources.c"),
                        "-o", str(work / "collector")], check=True)
        ram = work / "ram"
        with ram.open("wb") as backing:
            backing.truncate(1024 << 20)
        # This test's explicitly sized q35 RAM lies wholly below the PCI hole;
        # the integration driver uses the public transport's identity map.
        command = ["qemu-system-x86_64", "-machine", "q35,accel=tcg,memory-backend=ram0",
                   "-cpu", "max", "-smp", "4", "-m", "1024", "-object",
                   f"memory-backend-file,id=ram0,size=1024M,mem-path={ram},share=on",
                   "-kernel", str(base / "kernel"), "-initrd", str(base / "initrd.gz"),
                   "-append", "console=ttyS0 panic=-1 antinomie_boot_gpa=0x30000000",
                   "-snapshot", "-drive", f"file={str(base / 'base.qcow2').replace(',', ',,')},format=qcow2,if=virtio",
                   "-serial", f"file:{work}/serial.log", "-display", "none", "-monitor", "none",
                   "-no-reboot", "-nic", "none"]
        print(json.dumps({"base": str(base), "cpus": 4, "ram_mib": 1024, "accel": "tcg"}), flush=True)
        with (work / "qemu.log").open("w") as log:
            qemu = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                    env={**os.environ, "TMPDIR": str(work)})
            try:
                result = subprocess.run([str(work / "control"), str(ram), str(work / "collector")],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=110)
                print(result.stdout, end="", flush=True)
                if result.returncode or "GUEST RESOURCE CONTROL PASS" not in result.stdout:
                    print((work / "qemu.log").read_text(errors="replace"))
                    print((work / "serial.log").read_text(errors="replace"))
                    raise SystemExit(f"collector control qualification failed: {result.returncode}")
                serial = (work / "serial.log").read_text(errors="replace")
                if any(marker in serial for marker in ("Kernel panic", "BUG:", "WARNING: CPU:")):
                    raise SystemExit("kernel failure in collector control qualification")
            finally:
                if qemu.poll() is None:
                    qemu.terminate()
                    try:
                        qemu.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        qemu.kill()
                        qemu.wait()


if __name__ == "__main__":
    main()
