#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""sinkhole — the host-side listener for the Antinomie behavior samples.

Run it from the repository root, then point the samples at the address it prints:

    python3 tests/monitor/sinkhole.py                      # listen on 127.0.0.1
    python3 tests/monitor/sinkhole.py --nat        # listen on 0.0.0.0 for a NAT guest

    ./demo-all --host 127.0.0.1                         # on the same machine
    ./demo-all --host 10.0.2.2                          # in a QEMU NAT guest (with --nat)

It answers every protocol the samples speak, so each one goes down its whole
path: HTTP (check-in, GET /install.sh and /payload.elf, upload), TLS (the
ClientHello is read and refused with an alert), UDP, DNS, an SSH banner, IRC
and a sink for the reverse-shell echo. Nothing here sends a command or
executes anything: the shell sink only reads. Each request is logged on one
aligned line, filed under the scenario that sent it, and Ctrl-C prints a
per-scenario summary. Nothing leaves the machine.

Port 53 needs root. Without it the DNS listener falls back to --dns-port 5353
and the banner says to pass the same --dns-port to the samples.
"""

import argparse
import collections
import hashlib
import json
import os
import re
import signal
import socket
import struct
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- fixed payloads ------------------------------------------------------------------
#
# The samples compile in the SHA-256 of these exact bytes and run a download
# only when it matches (see samples.h). tests/monitor/test-sinkhole.py
# checks that the constants and these bytes agree.

DOWNLOAD_SCRIPT = (
    b"#!/bin/sh\n"
    b'echo "hello from demo download"\n'
    b"echo download ran > download-marker.txt\n"
)


def elf_payload():
    """A 187-byte static x86-64 ELF that writes a line to stdout and exits 0."""
    message = b"hello from demo download elf\n"
    base = 0x400000
    header_size, phdr_size = 64, 56
    code_at = header_size + phdr_size
    code = (
        b"\xb8\x01\x00\x00\x00"  # mov eax, 1 (write)
        b"\xbf\x01\x00\x00\x00"  # mov edi, 1 (stdout)
        b"\x48\x8d\x35\x10\x00\x00\x00"  # lea rsi, [rip + 16] -> message
        + b"\xba" + struct.pack("<I", len(message))  # mov edx, len
        + b"\x0f\x05"  # syscall
        b"\xb8\x3c\x00\x00\x00"  # mov eax, 60 (exit)
        b"\x31\xff"  # xor edi, edi
        b"\x0f\x05"  # syscall
    )
    total = code_at + len(code) + len(message)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    elf_header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, base + code_at, header_size, 0, 0, header_size, phdr_size, 1, 0, 0, 0
    )
    program_header = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, total, total, 0x1000)
    return elf_header + program_header + code + message


ELF_PAYLOAD = elf_payload()
DOWNLOAD_SHA256 = hashlib.sha256(DOWNLOAD_SCRIPT).hexdigest()
ELF_SHA256 = hashlib.sha256(ELF_PAYLOAD).hexdigest()

# Scenarios that talk to a listener, in storyline order, for the exit summary.
NETWORK_SCENARIOS = (
    "recon", "cred-read", "download", "download-elf", "http-beacon", "beacon-loop", "dns-tunnel",
    "dga", "tls-sni", "udp-beacon", "c2-misc", "shell-sim", "exfil-sim", "impact-sim",
)
BODY_MAX = 64 * 1024
STAGE_TO_SCENARIO = {"recon": "recon", "creds": "cred-read", "checkin": "http-beacon"}
DGA_NAME = re.compile(r"^[a-z]{10,18}\.(com|net|org|info|biz)$")
CONTROL_NAME = "update.example-cdn.invalid"


def preview(data, limit=200):
    text = bytes(data[:limit]).decode("utf-8", "replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text + ("..." if len(data) > limit else "")


def quote(data, limit=200):
    """preview() inside single quotes, for a log line."""
    return "'" + preview(data, limit).replace("'", "\\'") + "'"


def parse_sni(data):
    """Return the server_name of a TLS ClientHello, or None."""
    try:
        if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 9 + 2 + 32  # record + handshake header, version, random
        pos += 1 + data[pos]  # session id
        pos += 2 + int.from_bytes(data[pos : pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # compression methods
        total = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        end = min(len(data), pos + total)
        while pos + 4 <= end:
            kind = int.from_bytes(data[pos : pos + 2], "big")
            length = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if pos + length > end:
                return None
            if kind == 0:  # server_name
                name_len = int.from_bytes(data[pos + 3 : pos + 5], "big")
                return data[pos + 5 : pos + 5 + name_len].decode("ascii", "replace")
            pos += length
    except (IndexError, ValueError):
        return None
    return None


def parse_question(packet):
    """Return (id, name, type, question bytes) of a DNS packet, or None."""
    if len(packet) < 17:
        return None
    pos, labels = 12, []
    while pos < len(packet) and packet[pos] != 0:
        length = packet[pos]
        if length > 63 or pos + 1 + length > len(packet):
            return None
        labels.append(packet[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    pos += 1
    if pos + 4 > len(packet):
        return None
    qtype = int.from_bytes(packet[pos : pos + 2], "big")
    return packet[0:2], ".".join(labels).lower(), qtype, packet[12 : pos + 4]


def dns_reply(packet, mode, answer_ip):
    """Build the reply and say what it was: (bytes, label, qname, qtype)."""
    parsed = parse_question(packet)
    if not parsed:
        return None
    ident, name, qtype, question = parsed
    nxdomain = (
        mode == "nxdomain"
        or (mode == "auto" and (name.endswith(".onion") or DGA_NAME.match(name)))
    )
    if nxdomain:
        header = ident + b"\x81\x83" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
        return header + question, "NXDOMAIN", name, qtype
    answer = b""
    if qtype == 1:
        rdata = socket.inet_aton(answer_ip)
        answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack(">IH", 60, len(rdata)) + rdata
    elif qtype == 16:
        text = b"demo-sinkhole"
        rdata = bytes([len(text)]) + text
        answer = b"\xc0\x0c\x00\x10\x00\x01" + struct.pack(">IH", 60, len(rdata)) + rdata
    count = b"\x00\x01" if answer else b"\x00\x00"
    header = ident + b"\x81\x80" + b"\x00\x01" + count + b"\x00\x00\x00\x00"
    return header + question + answer, "answer" if answer else "empty", name, qtype


def classify_name(name):
    if name.endswith(".exfil.example-dns.invalid"):
        return "dns-tunnel"
    if name == CONTROL_NAME or DGA_NAME.match(name):
        return "dga"
    if name.endswith(".onion") or name in ("pastebin.com", "api.telegram.org"):
        return "c2-misc"
    return "unknown"


def classify_http(port_alt, method, path, host, body):
    host = (host or "").split(":")[0].lower()
    if path.startswith("/install.sh"):
        return "download"
    if path.startswith("/payload.elf"):
        return "download-elf"
    if path.startswith("/download.bin"):
        return "download"
    if path.startswith("/upload/"):
        return "exfil-sim"
    if path.startswith("/ping.php"):
        return "beacon-loop"
    if port_alt or host.endswith(".onion") or host in ("api.telegram.org", "169.254.169.254"):
        return "c2-misc"
    if path.startswith("/gate.php"):
        match = re.search(rb"scenario=([a-z0-9-]+)", body or b"")
        if match:
            return match.group(1).decode()
        match = re.search(rb"stage=([a-z]+)", body or b"")
        if match:
            return STAGE_TO_SCENARIO.get(match.group(1).decode(), "unknown")
    return "unknown"


# ---- the sinkhole -----------------------------------------------------------------------


class Stats:
    """Per-scenario counters; thread safe."""

    def __init__(self):
        self.lock = threading.Lock()
        self.data = collections.defaultdict(
            lambda: {"events": 0, "bytes": 0, "protos": collections.Counter(), "first": None, "last": None}
        )

    def add(self, scenario, proto, nbytes):
        now = time.time()
        with self.lock:
            entry = self.data[scenario]
            entry["events"] += 1
            entry["bytes"] += nbytes
            entry["protos"][proto] += 1
            entry["first"] = entry["first"] or now
            entry["last"] = now

    def snapshot(self):
        with self.lock:
            return {name: dict(entry, protos=dict(entry["protos"])) for name, entry in self.data.items()}


class Sink:
    """Listeners, the log, and the shutdown. One instance per run."""

    SHOWN = 5  # lines logged in full per (protocol, scenario) before rate limiting
    EVERY = 100  # then one line per this many

    def __init__(self, options, out=None):
        self.options = options
        self.out = out or sys.stdout
        self.stop = threading.Event()
        self.stats = Stats()
        self.lock = threading.Lock()
        self.seen = collections.Counter()
        self.log_file = None
        self.threads = []
        self.http_servers = []
        self.sockets = []
        self.bound = {}
        self.pwned_shown = False
        self.dns_port = options.dns_port

    # -- logging --

    def open_log(self):
        path = self.options.log
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.log_file = os.fdopen(fd, "w", encoding="utf-8")

    def emit(self, line):
        with self.lock:
            print(line, file=self.out, flush=True)
            if self.log_file:
                self.log_file.write(line + "\n")
                self.log_file.flush()

    def event(self, proto, scenario, peer, message, nbytes=0):
        """One aligned line: time, protocol, peer, scenario, message."""
        self.stats.add(scenario, proto, nbytes)
        key = (proto, scenario)
        with self.lock:
            self.seen[key] += 1
            count = self.seen[key]
        if count > self.SHOWN and count % self.EVERY != 0:
            return
        suffix = "" if count <= self.SHOWN else f"  [{count} so far, showing every {self.EVERY}th]"
        stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
        self.emit(f"{stamp}  {proto:<5} {peer:<21} {scenario:<12} {message}{suffix}")
        if self.options.pwned:
            self.pwned(proto, peer, nbytes)

    def pwned(self, proto, peer, nbytes):
        with self.lock:
            first = not self.pwned_shown
            self.pwned_shown = True
        if first:
            bar = "=" * 68
            self.emit(f"\n{bar}\n  {self.options.pwned}  -  payload received on the host listener\n{bar}\n")
        self.emit(f"{'':<12}PWNED {proto} {nbytes}B from {peer}")

    def info(self, message):
        stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
        self.emit(f"{stamp}  {'sink':<5} {'':<21} {'':<12} {message}")

    # -- listeners --

    def thread(self, target, *args):
        worker = threading.Thread(target=target, args=args, daemon=True)
        worker.start()
        self.threads.append(worker)

    def listen_tcp(self, label, port, handler):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.options.host, port))
        listener.listen(16)
        listener.settimeout(0.2)
        self.sockets.append(listener)
        self.bound[label] = listener.getsockname()[1]

        def serve():
            while not self.stop.is_set():
                try:
                    client, peer = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                self.thread(self.serve_client, handler, client, peer)

        self.thread(serve)

    def serve_client(self, handler, client, peer):
        with client:
            client.settimeout(2.0)
            try:
                handler(client, f"{peer[0]}:{peer[1]}")
            except (OSError, ValueError) as error:
                self.info(f"{peer[0]}:{peer[1]} connection error: {error}")

    def listen_http(self, label, port, alt):
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "Apache/2.4.58"
            sys_version = ""
            timeout = 3

            def handle_request(self):
                try:
                    length = max(0, int(self.headers.get("Content-Length") or 0))
                except ValueError:
                    length = 0
                body = self.rfile.read(min(length, BODY_MAX)) if length else b""
                if length > BODY_MAX:
                    self.close_connection = True
                path = self.path.split("?")[0]
                scenario = classify_http(alt, self.command, self.path, self.headers.get("Host"), body)
                status, ctype, reply = sink.route(self.command, path)
                peer = f"{self.client_address[0]}:{self.client_address[1]}"
                sink.event(
                    "http", scenario, peer,
                    f"{self.command} {self.path} -> {status} host={self.headers.get('Host')!r} "
                    f"len={length} body={quote(body, 80)}",
                    len(body) + len(self.path),
                )
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(reply)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(reply)
                self.close_connection = True

            do_GET = do_POST = do_PUT = do_HEAD = handle_request

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer((self.options.host, port), Handler)
        server.daemon_threads = True
        self.http_servers.append(server)
        self.bound[label] = server.server_address[1]
        self.thread(server.serve_forever, 0.2)

    @staticmethod
    def route(method, path):
        if method == "PUT" or path.startswith("/upload/"):
            return 201, "application/json", b'{"ok":true,"stored":true}'
        if path == "/install.sh":
            return 200, "text/x-shellscript", DOWNLOAD_SCRIPT
        if path == "/payload.elf":
            return 200, "application/octet-stream", ELF_PAYLOAD
        if path == "/download.bin":
            return 200, "application/octet-stream", b"DEMO-DECOY-NOT-AN-EXECUTABLE\n" * 4
        if path == "/gate.php":
            return 200, "application/json", b'{"ok":true,"cmd":"sleep","interval":60}'
        return 200, "application/json", b'{"ok":true}'

    def tls_handler(self, alt):
        def handle(client, peer):
            hello = client.recv(4096)
            sni = parse_sni(hello)
            scenario = "tls-sni" if sni == CONTROL_NAME and not alt else "c2-misc"
            if sni is None and not hello:
                scenario = "unknown"
            self.event("tls", scenario, peer, f"ClientHello {len(hello)}B SNI={sni or 'none'} -> alert", len(hello))
            # A fatal handshake_failure alert: the connection was accepted and read.
            client.sendall(b"\x15\x03\x03\x00\x02\x02\x28")

        return handle

    def ssh_handler(self, client, peer):
        client.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        banner = client.recv(256)
        self.event("ssh", "c2-misc", peer, f"client banner {quote(banner, 60)}", len(banner))

    def irc_handler(self, client, peer):
        data = client.recv(2048)
        text = data.decode("utf-8", "replace")
        if text.lstrip().startswith("{"):
            reply = b'{"id":1,"jsonrpc":"2.0","error":{"code":-1,"message":"sinkhole"}}\n'
            kind = "stratum login"
        else:
            reply = b":sink.invalid 001 demo-sample :Welcome\r\nPING :sink.invalid\r\n"
            kind = "irc"
        self.event("tcp", "c2-misc", peer, f"{kind} {quote(data, 80)}", len(data))
        client.sendall(reply)

    def shell_handler(self, client, peer):
        """Reads whatever the reverse shell prints. Never sends anything back."""
        chunks, total = [], 0
        while total < 4096:
            try:
                chunk = client.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        self.event("shell", "shell-sim", peer, f"reverse-shell output {quote(data, 100)}", len(data))

    def listen_udp(self, label, port, handler):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.options.host, port))
        except OSError:
            sock.close()
            raise
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.settimeout(0.2)
        self.sockets.append(sock)
        self.bound[label] = sock.getsockname()[1]

        def serve():
            while not self.stop.is_set():
                try:
                    payload, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    reply = handler(payload, f"{peer[0]}:{peer[1]}")
                    if reply:
                        sock.sendto(reply, peer)
                except OSError:
                    pass

        self.thread(serve)

    def udp_handler(self, payload, peer):
        scenario = "unknown"
        try:
            scenario = json.loads(payload.decode("utf-8", "replace")).get("scenario", "udp-beacon")
        except ValueError:
            if payload.startswith(b"ping"):
                scenario = "impact-sim"
        self.event("udp", scenario, peer, f"{len(payload)}B {quote(payload, 90)}", len(payload))
        if payload.startswith(b"ping"):
            return None  # the datagram burst: no reply to each of a thousand packets
        return b'{"ok":true,"stage":"sinkhole"}'

    def dns_handler(self, payload, peer):
        built = dns_reply(payload, self.options.dns_mode, self.options.dns_answer)
        if not built:
            return None
        reply, label, name, qtype = built
        names = {1: "A", 16: "TXT", 28: "AAAA"}
        self.event("dns", classify_name(name), peer, f"{names.get(qtype, qtype)} {name} -> {label}", len(payload))
        return reply

    # -- run --

    def start(self):
        options = self.options
        self.open_log()
        self.listen_http("http", options.http_port, False)
        self.listen_http("http-alt", options.alt_http_port, True)
        self.listen_tcp("tls", options.tls_port, self.tls_handler(False))
        self.listen_tcp("tls-alt", options.alt_tls_port, self.tls_handler(True))
        self.listen_tcp("ssh", options.ssh_port, self.ssh_handler)
        self.listen_tcp("irc", options.irc_port, self.irc_handler)
        self.listen_tcp("shell", options.shell_port, self.shell_handler)
        self.listen_udp("udp", options.udp_port, self.udp_handler)
        try:
            self.listen_udp("dns", options.dns_port, self.dns_handler)
        except PermissionError:
            if options.dns_port_given:
                raise
            self.dns_port = 5353
            self.listen_udp("dns", 5353, self.dns_handler)
            self.info("DNS port 53 needs root: listening on 5353 instead; pass --dns-port 5353 to the samples")
        self.dns_port = self.bound["dns"]

    def shutdown(self):
        """Stop every listener, wait for the threads, close the log."""
        self.stop.set()
        for server in self.http_servers:
            server.shutdown()
            server.server_close()
        for sock in self.sockets:
            sock.close()
        for worker in self.threads:
            worker.join(timeout=2.0)
        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def banner(self):
        options = self.options
        listen = options.host
        guest = options.guest_host
        rows = [
            ("http", "http", "GET /install.sh /payload.elf, POST /gate.php, PUT /upload"),
            ("http-alt", "http", "off-standard HTTP port (c2-misc)"),
            ("tls", "tls", "ClientHello read, answered with an alert (tls-sni)"),
            ("tls-alt", "tls", "off-standard TLS port (c2-misc)"),
            ("udp", "udp", "JSON check-ins and the datagram burst"),
            ("dns", "udp", f"A/TXT, NXDOMAIN for DGA names, mode {options.dns_mode}"),
            ("ssh", "tcp", "SSH banner (c2-misc)"),
            ("irc", "tcp", "IRC and Stratum text (c2-misc)"),
            ("shell", "tcp", "reverse-shell echo sink, read-only (shell-sim)"),
        ]
        lines = ["", f"Demo sinkhole           log: {options.log}", ""]
        lines.append(f"  {'listener':<9} {'address':<22} serves")
        for label, _, what in rows:
            lines.append(f"  {label:<9} {listen + ':' + str(self.bound[label]):<22} {what}")
        flags = f"--host {guest}"
        if self.dns_port != 53:
            flags += f" --dns-port {self.dns_port}"
        lines += [
            "",
            f"  Give the samples:  {flags}",
            f"    ./demo-all {flags}                 # every scenario, in phase order",
            f"    ./demo-download {flags}              # one scenario",
        ]
        if options.nat:
            lines.append("  NAT guest: QEMU user networking reaches this machine at 10.0.2.2 "
                         "(set the VM's network to NAT, not Isolated).")
        elif listen == "0.0.0.0":
            lines.append(f"  Listening on every interface; --host must be an address of this machine "
                         f"as the guest reaches it (shown: {guest}).")
        lines += ["  Ctrl-C stops the sinkhole and prints a per-scenario summary.", ""]
        self.emit("\n".join(lines))
        self.emit(f"{'time':<12}  {'proto':<5} {'peer':<21} {'scenario':<12} request")

    def summary(self):
        snapshot = self.stats.snapshot()
        lines = ["", "Per-scenario summary", f"  {'scenario':<13} {'events':>6} {'bytes':>8}  protocols"]
        names = list(NETWORK_SCENARIOS) + sorted(set(snapshot) - set(NETWORK_SCENARIOS))
        total = 0
        for name in names:
            entry = snapshot.get(name)
            if not entry:
                lines.append(f"  {name:<13} {0:>6} {0:>8}  -")
                continue
            protos = " ".join(f"{proto}={count}" for proto, count in sorted(entry["protos"].items()))
            lines.append(f"  {name:<13} {entry['events']:>6} {entry['bytes']:>8}  {protos}")
            total += entry["events"]
        lines.append(f"  {'total':<13} {total:>6}")
        silent = [name for name in NETWORK_SCENARIOS if name not in snapshot]
        if silent:
            lines.append(f"  no traffic from: {', '.join(silent)}")
        return "\n".join(lines)


def default_log_path():
    directory = os.path.join(tempfile.gettempdir(), f"demo-sinkhole-{os.getuid()}")
    return os.path.join(directory, "sinkhole.log")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Local listener for the behavior samples (see the module docstring).",
        epilog="Stop with Ctrl-C. Run from the repository root: "
        "python3 tests/monitor/sinkhole.py",
    )
    parser.add_argument("--host", default="127.0.0.1", metavar="ADDR",
                        help="address to listen on (default 127.0.0.1); also the --host to give the samples")
    parser.add_argument("--nat", action="store_true",
                        help="listen on 0.0.0.0 and show 10.0.2.2, the host as a QEMU NAT guest sees it")
    parser.add_argument("--guest-host", metavar="ADDR", help="the --host to show for the samples")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--tls-port", type=int, default=8443)
    parser.add_argument("--udp-port", type=int, default=4444)
    parser.add_argument("--dns-port", type=int, default=None,
                        help="default 53, or 5353 when 53 needs root")
    parser.add_argument("--alt-http-port", type=int, default=9080)
    parser.add_argument("--alt-tls-port", type=int, default=9443)
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--irc-port", type=int, default=6667)
    parser.add_argument("--shell-port", type=int, default=4445)
    parser.add_argument("--dns-mode", choices=("auto", "answer", "nxdomain"), default="auto",
                        help="auto: answer names, NXDOMAIN for DGA-looking and .onion names")
    parser.add_argument("--dns-answer", default=None, metavar="IP",
                        help="address in A answers (default: the address shown for the samples)")
    parser.add_argument("--log", default=None, metavar="PATH",
                        help="log file (default: a per-user file under the system temp directory)")
    parser.add_argument("--summary-json", metavar="PATH", help="also write the exit summary as JSON")
    parser.add_argument("--pwned", nargs="?", const="PWNED", default=None, metavar="TEXT",
                        help="print a banner and a PWNED line when a payload arrives")
    options = parser.parse_args(argv)
    options.dns_port_given = options.dns_port is not None
    if options.dns_port is None:
        options.dns_port = 53
    if options.nat:
        options.host = "0.0.0.0"
    options.guest_host = options.guest_host or ("10.0.2.2" if options.nat else options.host)
    if options.guest_host == "0.0.0.0":
        options.guest_host = "127.0.0.1"
    options.dns_answer = options.dns_answer or options.guest_host
    options.log = options.log or default_log_path()
    return options


def main(argv=None):
    options = parse_args(argv)
    sink = Sink(options)
    try:
        sink.start()
    except OSError as error:
        sink.shutdown()
        print(f"sinkhole: cannot listen: {error}", file=sys.stderr)
        return 1
    sink.banner()

    def request_stop(signum, frame):
        sink.stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    while not sink.stop.wait(0.2):
        pass
    sink.shutdown()
    print(sink.summary(), flush=True)
    if options.summary_json:
        with open(options.summary_json, "w", encoding="utf-8") as handle:
            json.dump(sink.stats.snapshot(), handle, indent=2, sort_keys=True)
    print(f"\nlog: {options.log}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
