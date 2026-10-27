#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""tests/monitor/sinkhole.py and the behavior samples' registry, without a VM.

Run from the repository root: python3 tests/monitor/test-sinkhole.py
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import struct
import subprocess
import tempfile
import time
import unittest
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("sinkhole", HERE / "sinkhole.py")
sink_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sink_module)

HEADER = (HERE / "behavior-samples" / "samples.h").read_text()
REGISTRY = (HERE / "behavior-samples" / "main.c").read_text()
RULES_TABLE = ROOT / "src/antinomie/monitor/crates/monitor-ui/src/triage/rules/table.rs"


def define(name):
    return re.search(rf'#define {name} "([^"]+)"', HEADER).group(1)


def client_hello(server_name):
    """The ClientHello the samples send, built the same way as beaconing.c does."""
    name = server_name.encode()
    sni = b"\x00" + struct.pack(">H", len(name)) + name
    sni_list = struct.pack(">H", len(sni)) + sni
    extension = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list
    body = (
        b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x04\x00\x2f\x00\x35" + b"\x01\x00"
        + struct.pack(">H", len(extension)) + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def dns_query(name, qtype=1):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00" + struct.pack(">HH", qtype, 1)


class Payloads(unittest.TestCase):
    def test_pinned_hashes_match_the_header(self):
        self.assertEqual(define("SAMPLE_DOWNLOAD_SHA256"), hashlib.sha256(sink_module.DOWNLOAD_SCRIPT).hexdigest())
        self.assertEqual(define("SAMPLE_ELF_SHA256"), hashlib.sha256(sink_module.ELF_PAYLOAD).hexdigest())
        self.assertEqual(define("SAMPLE_DOWNLOAD_PATH"), "/install.sh")
        self.assertEqual(define("SAMPLE_ELF_PATH"), "/payload.elf")

    def test_script_is_the_hello_world_from_the_header(self):
        lines = HEADER[HEADER.index("#define SAMPLE_DOWNLOAD_TEXT"):].splitlines()
        block = []
        for line in lines[:8]:
            block.append(line.rstrip("\\"))
            if not line.endswith("\\"):
                break
        text = "\n".join(block)
        pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
        script = "".join(pieces).encode().decode("unicode_escape").encode()
        self.assertEqual(script, sink_module.DOWNLOAD_SCRIPT)
        self.assertTrue(script.startswith(b"#!/bin/sh\n"))
        self.assertIn(b"hello from demo download", script)

    @unittest.skipUnless(platform.machine() == "x86_64" and platform.system() == "Linux", "x86-64 Linux only")
    def test_the_elf_runs_and_says_hello(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.elf"
            path.write_bytes(sink_module.ELF_PAYLOAD)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
            done = subprocess.run([str(path)], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, b"hello from demo download elf\n")

    def test_the_elf_is_small_and_starts_with_the_magic(self):
        self.assertLess(len(sink_module.ELF_PAYLOAD), 512)
        self.assertEqual(sink_module.ELF_PAYLOAD[:4], b"\x7fELF")


class Parsers(unittest.TestCase):
    def test_sni(self):
        self.assertEqual(sink_module.parse_sni(client_hello("update.example-cdn.invalid")), "update.example-cdn.invalid")
        self.assertIsNone(sink_module.parse_sni(b"GET / HTTP/1.1\r\n"))
        self.assertIsNone(sink_module.parse_sni(client_hello("x")[:20]))

    def test_dns_policy(self):
        def rcode(name, mode="auto", qtype=1):
            reply = sink_module.dns_reply(dns_query(name, qtype), mode, "127.0.0.1")[0]
            return reply[3] & 15, reply

        self.assertEqual(rcode("yvoiiptwgtbdovnn.com")[0], 3)
        self.assertEqual(rcode("abcdefghijklmnop.onion")[0], 3)
        self.assertEqual(rcode("update.example-cdn.invalid")[0], 0)
        self.assertEqual(rcode("pastebin.com")[0], 0)
        self.assertEqual(rcode("pastebin.com", "nxdomain")[0], 3)
        self.assertEqual(rcode("yvoiiptwgtbdovnn.com", "answer")[0], 0)
        code, reply = rcode("c01.exfil.example-dns.invalid", qtype=16)
        self.assertEqual(code, 0)
        self.assertIn(b"demo-sinkhole", reply)
        self.assertIsNone(sink_module.dns_reply(b"short", "auto", "127.0.0.1"))

    def test_scenario_classification(self):
        classify = sink_module.classify_http
        self.assertEqual(classify(False, "GET", "/install.sh", "10.0.2.2", b""), "download")
        self.assertEqual(classify(False, "GET", "/payload.elf", "10.0.2.2", b""), "download-elf")
        self.assertEqual(classify(False, "POST", "/gate.php", "10.0.2.2", b"stage=creds&files=3"), "cred-read")
        self.assertEqual(classify(False, "POST", "/gate.php", "10.0.2.2", b"x&scenario=http-beacon"), "http-beacon")
        self.assertEqual(classify(False, "GET", "/", "api.telegram.org", b""), "c2-misc")
        self.assertEqual(classify(True, "GET", "/gate.php?stage=alt", "10.0.2.2", b""), "c2-misc")
        self.assertEqual(sink_module.classify_name("c01.exfil.example-dns.invalid"), "dns-tunnel")
        self.assertEqual(sink_module.classify_name("update.example-cdn.invalid"), "dga")


class Registry(unittest.TestCase):
    def test_expected_rule_ids_exist_in_the_rules_table(self):
        table = set(re.findall(r'rule\(\s*"([a-z_]+\.[a-z_]+)"', RULES_TABLE.read_text()))
        self.assertGreater(len(table), 100)
        start = REGISTRY.index("static const struct module modules[]")
        end = REGISTRY.index("#define MODULE_COUNT")
        used = set(re.findall(r'\b((?:[a-z]+)\.(?:[a-z_]+))(?=[,"])', REGISTRY[start:end]))
        prefixes = {rule.split(".")[0] for rule in table}
        used = {name for name in used if name.split(".")[0] in prefixes}
        self.assertGreater(len(used), 80)
        self.assertEqual(sorted(used - table), [])


class Running(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        log = os.path.join(self.directory.name, "sub", "sinkhole.log")
        options = sink_module.parse_args(
            ["--http-port", "0", "--alt-http-port", "0", "--tls-port", "0", "--alt-tls-port", "0",
             "--udp-port", "0", "--dns-port", "0", "--ssh-port", "0", "--irc-port", "0",
             "--shell-port", "0", "--log", log]
        )
        self.out = io.StringIO()
        self.sink = sink_module.Sink(options, out=self.out)
        self.sink.start()
        self.sink.banner()
        self.log = log

    def tearDown(self):
        self.sink.shutdown()
        self.directory.cleanup()

    def port(self, label):
        return self.sink.bound[label]

    def test_http_serves_the_pinned_payloads_and_answers_the_gate(self):
        base = f"http://127.0.0.1:{self.port('http')}"
        self.assertEqual(urllib.request.urlopen(base + "/install.sh", timeout=5).read(), sink_module.DOWNLOAD_SCRIPT)
        self.assertEqual(urllib.request.urlopen(base + "/payload.elf", timeout=5).read(), sink_module.ELF_PAYLOAD)
        request = urllib.request.Request(base + "/gate.php", data=b"stage=checkin&scenario=http-beacon", method="POST")
        reply = json.loads(urllib.request.urlopen(request, timeout=5).read())
        self.assertTrue(reply["ok"])
        upload = urllib.request.Request(base + "/upload/x", data=b"abc", method="PUT")
        self.assertEqual(urllib.request.urlopen(upload, timeout=5).status, 201)

    def test_tls_is_accepted_and_refused_with_an_alert(self):
        with socket.create_connection(("127.0.0.1", self.port("tls")), timeout=5) as client:
            client.sendall(client_hello("update.example-cdn.invalid"))
            self.assertEqual(client.recv(16)[:1], b"\x15")
        self.wait_for("SNI=update.example-cdn.invalid")

    def test_udp_dns_and_banners(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            udp.sendto(b'{"scenario":"udp-beacon"}', ("127.0.0.1", self.port("udp")))
            self.assertIn(b"sinkhole", udp.recv(256))
            udp.sendto(dns_query("update.example-cdn.invalid"), ("127.0.0.1", self.port("dns")))
            self.assertEqual(udp.recv(512)[3] & 15, 0)
            udp.sendto(dns_query("yvoiiptwgtbdovnn.com"), ("127.0.0.1", self.port("dns")))
            self.assertEqual(udp.recv(512)[3] & 15, 3)
        with socket.create_connection(("127.0.0.1", self.port("ssh")), timeout=5) as client:
            self.assertTrue(client.recv(64).startswith(b"SSH-2.0-"))
        with socket.create_connection(("127.0.0.1", self.port("shell")), timeout=5) as client:
            client.sendall(b"sample reverse-shell demo\n")
        self.wait_for("reverse-shell output")

    def wait_for(self, text):
        deadline = time.time() + 5
        while time.time() < deadline:
            if text in self.out.getvalue():
                return
            time.sleep(0.05)
        self.fail(f"{text!r} not logged:\n{self.out.getvalue()}")

    def test_log_lines_are_aligned_and_the_log_is_not_in_the_working_directory(self):
        urllib.request.urlopen(f"http://127.0.0.1:{self.port('http')}/install.sh", timeout=5).read()
        self.wait_for("GET /install.sh")
        row = next(line for line in self.out.getvalue().splitlines()
                   if "GET /install.sh" in line and line[:1].isdigit())
        self.assertRegex(row, r"^\d\d:\d\d:\d\d\.\d{3}  http  127\.0\.0\.1:\d+\s+download\s+GET /install\.sh")
        self.assertEqual(row.index("download"), 12 + 2 + 5 + 1 + 21 + 1)
        self.assertTrue(os.path.exists(self.log))
        self.assertNotEqual(os.path.dirname(os.path.abspath(self.log)), os.getcwd())

    def test_banner_names_the_host_flag(self):
        text = self.out.getvalue()
        self.assertIn("--host 127.0.0.1", text)
        for label in ("http", "tls", "udp", "dns", "ssh", "irc", "shell"):
            self.assertIn(f"127.0.0.1:{self.port(label)}", text)

    def test_shutdown_is_clean_and_the_summary_names_each_scenario(self):
        urllib.request.urlopen(f"http://127.0.0.1:{self.port('http')}/install.sh", timeout=5).read()
        started = time.time()
        self.sink.shutdown()
        self.assertLess(time.time() - started, 5)
        self.assertTrue(all(not worker.is_alive() for worker in self.sink.threads))
        summary = self.sink.summary()
        self.assertRegex(summary, r"download\s+1")
        self.assertIn("no traffic from:", summary)
        self.assertIn("dns-tunnel", summary)

    def test_default_log_is_under_the_temp_directory(self):
        path = sink_module.default_log_path()
        self.assertTrue(path.startswith(tempfile.gettempdir()))
        self.assertNotIn(str(ROOT), path)


class Arguments(unittest.TestCase):
    def test_nat_listens_everywhere_and_shows_the_qemu_host(self):
        options = sink_module.parse_args(["--nat"])
        self.assertEqual(options.host, "0.0.0.0")
        self.assertEqual(options.guest_host, "10.0.2.2")
        self.assertEqual(options.dns_answer, "10.0.2.2")

    def test_default_listens_on_loopback(self):
        options = sink_module.parse_args([])
        self.assertEqual((options.host, options.guest_host), ("127.0.0.1", "127.0.0.1"))
        self.assertFalse(options.dns_port_given)


if __name__ == "__main__":
    unittest.main()
