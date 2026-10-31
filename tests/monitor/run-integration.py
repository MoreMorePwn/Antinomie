#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Boot an isolated test disk and exercise kernel control through public V7 APIs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
BUNDLE = REPO / "work/debian-6.12.94-1-trixie/images/monitor-base"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--boot-only", action="store_true")
    parser.add_argument("--output", type=Path, default=REPO / "work/monitor-results" / time.strftime("%Y%m%d-%H%M%S"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    disk = args.output / "disk.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(BUNDLE / "base.qcow2"), str(disk), "1G"], check=True)
    with tempfile.TemporaryDirectory(prefix="ant-monitor-", dir="/dev/shm") as temporary:
        ram = Path(temporary) / "ram"
        with ram.open("wb") as backing:
            backing.truncate(1024 << 20)
        command = ["qemu-system-x86_64", "-machine", f"q35,accel={args.accel},memory-backend=ram0",
                   "-cpu", "host" if args.accel == "kvm" else "max", "-smp", str(args.cpus), "-m", "1024",
                   "-object", f"memory-backend-file,id=ram0,size=1024M,mem-path={ram},share=on",
                   "-kernel", str(BUNDLE / "kernel"), "-initrd", str(BUNDLE / "initrd.gz"),
                   "-append", "console=ttyS0 panic=-1 antinomie_boot_gpa=0x30000000",
                   "-drive", f"file={disk},format=qcow2,if=virtio", "-serial", f"file:{args.output / 'serial.log'}",
                   "-display", "none", "-monitor", "none", "-no-reboot", "-nic", "none"]
        (args.output / "qemu.json").write_text(json.dumps(command, indent=2) + "\n")
        with (args.output / "qemu.log").open("w") as qemu_log:
            qemu = subprocess.Popen(command, stdout=qemu_log, stderr=subprocess.STDOUT)
            started = time.monotonic()
            try:
                deadline = started + 90
                while time.monotonic() < deadline:
                    if qemu.poll() is not None:
                        raise RuntimeError(f"QEMU exited {qemu.returncode}; inspect qemu.log")
                    serial = args.output / "serial.log"
                    if serial.exists() and "BusyBox guest ready" in serial.read_text(errors="replace"):
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("guest boot timeout; inspect serial.log")
                boot_seconds = time.monotonic() - started
                if not args.boot_only:
                    with (args.output / "host.log").open("w") as host_log:
                        subprocess.run([str(REPO / "work/monitor-integration"), str(ram), str(REPO / "work/monitor-probe")],
                                       stdout=host_log, stderr=subprocess.STDOUT, check=True, timeout=120)
                    qemu.wait(timeout=30)
                    if qemu.returncode:
                        raise RuntimeError(f"guest shutdown QEMU exit {qemu.returncode}")
                serial_text = (args.output / "serial.log").read_text(errors="replace")
                if any(marker in serial_text for marker in ("Kernel panic", "BUG:", "WARNING: CPU:")):
                    raise RuntimeError("kernel failure; inspect serial.log")
                (args.output / "result.json").write_text(json.dumps({"status": "PASS", "cpus": args.cpus,
                    "accel": args.accel, "boot_seconds": boot_seconds, "elapsed_seconds": time.monotonic()-started,
                    "boot_only": args.boot_only}, indent=2) + "\n")
                print(f"PASS {args.output}")
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
