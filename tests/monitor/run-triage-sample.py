#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Create an actual saved sample run in a fresh, standalone data directory.

Usage: run-triage-sample.py BASE_BUNDLE OUTPUT [--guest-run BINARY]
Requires Linux user/network namespaces, iproute2, gcc static libc and KVM/QEMU.
Only the sample guest executes the C workload. The owned namespace has loopback
only: HTTP/DNS fixtures cannot forward requests to the host's outside network.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socketserver
import struct
import subprocess
import sys
import threading


class HTTPFixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ANTINOMIE_TRIAGE_FIXTURE_v1\nbenign local HTTP response\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print("local HTTP: " + format_string % args, file=sys.stderr)


class DNSFixture(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        # Accept only this fixture's exact A question; never resolve or forward.
        question = b"\x06triage\x04test\0\0\x01\0\x01"
        if len(data) != 12 + len(question) or data[12:] != question:
            return
        header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([198, 51, 100, 42])
        connection.sendto(header + question + answer, self.client_address)
        print("local DNS: triage.test -> 198.51.100.42", file=sys.stderr)


def isolate_saved_vm(output, vm_id):
    """Disable routing on future boots, after the owned backend has shut down."""
    path = output / "data" / vm_id / "config.json"
    if path.resolve().parent.parent != (output / "data").resolve():
        raise ValueError("unexpected sample VM path")
    config = json.loads(path.read_text())
    if config["id"] != vm_id:
        raise ValueError("sample VM identity changed")
    config.update(nat=False, isolated_network=True)
    temporary = path.with_suffix(".sample-new")
    with temporary.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(config, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main():
    source = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--guest-run", type=Path, default=source / "src/antinomie/monitor/target/release/examples/guest-run")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside:
        os.execvp("unshare", ["unshare", "--user", "--map-root-user", "--net",
                            sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--inside"])
    # Prevent accidental use of --inside in the host's ordinary network namespace.
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if sorted(link["ifname"] for link in links) != ["lo"]:
        parser.error("sample requires its own network namespace with only loopback")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    base, output, harness = args.base.resolve(), args.output.resolve(), args.guest_run.resolve()
    if not (base / "bundle.json").is_file() or not harness.is_file():
        parser.error("verified base bundle and built guest-run harness are required")
    output.mkdir(parents=True, exist_ok=False)
    binary = output / "triage-sample"
    compiler = shutil.which("musl-gcc") or "gcc"
    headers = []
    if Path(compiler).name == "musl-gcc":
        multiarch = subprocess.check_output(["gcc", "-print-multiarch"], text=True).strip()
        headers = ["-idirafter", "/usr/include", "-idirafter", f"/usr/include/{multiarch}"]
    subprocess.run([compiler, "-static", "-O1", "-g", "-fno-omit-frame-pointer", "-pthread",
                    "-Wall", "-Wextra", "-Werror", *headers, str(source / "tests/monitor/triage-sample.c"),
                    "-o", str(binary)], check=True)
    plan = {
        "data_dir": str(output / "data"), "headless": True, "import": str(base),
        "quota_mib": 256, "boot_timeout": 90,
        "vm": {"name": "Triage sample 0.6.2", "cpus": 2, "ram_mib": 512,
               "disk_gib": 1, "nat": True,
               "transport": {"ring_kib": 4096, "lossless": True, "max_wait_ms": 100,
                             "event_table": 16384}},
        "uploads": [{"source": str(binary), "destination": "/tmp/triage-sample"}],
        "runs": [{"path": "/tmp/triage-sample", "uid": 0, "gid": 0,
                  "done": "TRIAGE SAMPLE DONE", "timeout": 120,
                  "analysis": {"enabled": True}, "capture_network": True,
                  "memory_dump_on_exit": True, "core_dump_on_exit": True}]
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    servers = [ThreadingHTTPServer(("127.0.0.1", 8080), HTTPFixture),
               socketserver.ThreadingUDPServer(("127.0.0.1", 53), DNSFixture)]
    threads = []
    try:
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        with (output / "backend.log").open("w") as log, (output / "run-report.json").open("w") as report:
            subprocess.run([str(harness), str(output / "plan.json")], stdout=report, stderr=log, check=True)
        report = json.loads((output / "run-report.json").read_text())
        if not all(run["marker_seen"] for run in report["runs"]):
            raise RuntimeError("sample completion marker missing; inspect recorded terminal")
        isolate_saved_vm(output, report["vm_id"])
        print(json.dumps({"data_dir": str(output / "data"), "runs": report["runs"],
                          "vm_id": report["vm_id"]}, indent=2))
    finally:
        for server in servers[:len(threads)]:
            server.shutdown()
        for server in servers:
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
