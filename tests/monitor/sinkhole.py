#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""sinkhole — a local listener for the Antinomie behavior samples.

The samples default to the QEMU user-network host (10.0.2.2). To see a complete
application-layer exchange, run this listener and point the sample at it, on
the guest's loopback or, for a NAT guest, on the host:

    python3 sinkhole.py --http-port 8080 --tls-port 8443 \
        --udp-port 4444 --dns-port 5353

    ./ant-sample-http-beacon --host 127.0.0.1 --port 8080 --rounds 1
    ./ant-sample-tls-sni    --host 127.0.0.1 --port 8443 --rounds 1
    ./ant-sample-udp-beacon --host 127.0.0.1 --port 4444 --rounds 1
    SAMPLE_DNS_PORT=5353 ./ant-sample-dns-tunnel --resolver 127.0.0.1 --rounds 1

For a NAT guest, run it on the host and reach it at the QEMU user-network
gateway (10.0.2.2). --nat binds 0.0.0.0 and prints the guest recipe; --pwned
prints a banner and a PWNED line whenever a payload arrives:

    python3 sinkhole.py --nat --pwned --http-port 8080 ...
    # in the guest:
    ./ant-sample-recon --host 10.0.2.2 --port 8080 --rounds 1

It logs each request to stdout and to --log (default sinkhole.log) and answers
so the sample's recv() path runs too. Nothing leaves the machine. Port 53 needs
root; use 5353 and SAMPLE_DNS_PORT otherwise. The sample's DNS client sends to
port 53 unless SAMPLE_DNS_PORT overrides it.
"""

import argparse
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
LOG_PATH = "sinkhole.log"
PWNED = False
PWNED_BANNER = "PWNED"
PWNED_ONCE = False
BODY_MAX = 64 * 1024


def log(proto, message):
    line = f"{time.strftime('%H:%M:%S')} {proto:<4} {message}"
    with LOCK:
        print(line, flush=True)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass


def pwned(proto, peer, nbytes, detail=""):
    """Banner on the first payload, then one PWNED line per hit."""
    global PWNED_ONCE
    if not PWNED:
        return
    if not PWNED_ONCE:
        PWNED_ONCE = True
        with LOCK:
            print("\n" + "=" * 68, flush=True)
            print(f"  {PWNED_BANNER}  -  payload received on the host listener", flush=True)
            print("=" * 68 + "\n", flush=True)
    log("PWN", f"PWNED {proto} {nbytes}B from {peer} {detail}".rstrip())


def preview(data, limit=512):
    text = data[:limit].decode("utf-8", "replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def parse_sni(data):
    """Return the server_name from a TLS ClientHello, or None."""
    try:
        if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 9  # record header + handshake type/length
        pos += 2  # legacy_version
        pos += 32  # random
        pos += 1 + data[pos]  # session_id
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


def http_server(host, port):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AntinomieSinkhole/1.0"

        def _handle(self):
            try:
                length = max(0, int(self.headers.get("Content-Length") or 0))
            except ValueError:
                length = 0
            # Bounded: with --nat the listener is reachable from the network.
            body = self.rfile.read(min(length, BODY_MAX)) if length else b""
            pwned("http", self.client_address[0], max(len(body), 1),
                  f"{self.command} {self.path}")
            log("http", f"{self.command} {self.path} UA={self.headers.get('User-Agent')!r} "
                        f"len={length} body={preview(body)!r}")
            reply = b'{"ok":true,"stage":"sinkhole"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        do_GET = _handle
        do_POST = _handle

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log("http", f"listening on {host}:{port}")


def tls_server(host, port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(8)
    log("tls", f"listening on {host}:{port}")

    def serve():
        while True:
            try:
                client, address = listener.accept()
            except OSError:
                return
            with client:
                try:
                    client.settimeout(2.0)
                    hello = client.recv(4096)
                    sni = parse_sni(hello)
                    pwned("tls", address[0], len(hello), f"SNI={sni or 'none'}")
                    log("tls", f"{address[0]}:{address[1]} ClientHello {len(hello)} bytes "
                               f"SNI={sni or 'none'}")
                    # handshake_failure alert so the sample's recv() returns data
                    client.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
                except OSError as error:
                    log("tls", f"{address[0]}:{address[1]} {error}")

    threading.Thread(target=serve, daemon=True).start()


def udp_server(host, port):
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind((host, port))
    log("udp", f"listening on {host}:{port}")

    def serve():
        while True:
            try:
                payload, address = sink.recvfrom(65535)
            except OSError:
                return
            pwned("udp", address[0], len(payload))
            log("udp", f"{address[0]}:{address[1]} {len(payload)} bytes {preview(payload)!r}")
            try:
                sink.sendto(b'{"ok":true,"stage":"sinkhole"}', address)
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()


def dns_answer(packet, mode, address):
    if len(packet) < 12:
        return None
    ident = packet[0:2]
    pos = 12
    while pos < len(packet) and packet[pos] != 0:
        pos += 1 + packet[pos]
    pos += 1
    if pos + 4 > len(packet):
        return None
    qtype = int.from_bytes(packet[pos : pos + 2], "big")
    question = packet[12 : pos + 4]
    name = packet[12 : pos]
    labels = []
    at = 0
    while at < len(name) and name[at] != 0:
        length = name[at]
        labels.append(name[at + 1 : at + 1 + length].decode("ascii", "replace"))
        at += 1 + length
    qname = ascii(".".join(labels))[1:-1]

    if mode == "nxdomain":
        header = ident + b"\x81\x83" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
        log("dns", f"qname={qname} type={qtype} -> NXDOMAIN")
        return header + question

    if qtype == 1 and address:
        rdata = socket.inet_aton(address)
        answer = b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + struct.pack(">IH", 60, len(rdata)) + rdata
    elif qtype == 16:
        text = b"antinomie-sinkhole"
        rdata = bytes([len(text)]) + text
        answer = b"\xc0\x0c" + b"\x00\x10" + b"\x00\x01" + struct.pack(">IH", 60, len(rdata)) + rdata
    else:
        answer = b""
    header = ident + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
    log("dns", f"qname={qname} type={qtype} -> answer")
    return header + question + answer


def dns_server(host, port, mode, address):
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sink.bind((host, port))
    except PermissionError:
        log("dns", f"cannot bind {host}:{port} (port 53 needs root); use --dns-port 5353 "
                   f"and SAMPLE_DNS_PORT=5353")
        return
    log("dns", f"listening on {host}:{port} mode={mode}")

    def serve():
        while True:
            try:
                packet, peer = sink.recvfrom(65535)
            except OSError:
                return
            pwned("dns", peer[0], len(packet))
            reply = dns_answer(packet, mode, address)
            if reply:
                try:
                    sink.sendto(reply, peer)
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--tls-port", type=int, default=8443)
    parser.add_argument("--udp-port", type=int, default=4444)
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--dns-mode", choices=("nxdomain", "answer"), default="nxdomain")
    parser.add_argument("--dns-answer", default="127.0.0.1")
    parser.add_argument("--log", default="sinkhole.log")
    parser.add_argument("--pwned", nargs="?", const="PWNED", default=None, metavar="TEXT",
                        help="print a banner when a payload arrives (optionally with TEXT)")
    parser.add_argument("--nat", action="store_true",
                        help="bind 0.0.0.0 and print the 10.0.2.2 recipe for a NAT guest")
    options = parser.parse_args()

    global LOG_PATH, PWNED, PWNED_BANNER
    LOG_PATH = options.log
    open(LOG_PATH, "w", encoding="utf-8").close()
    log("sink", f"logging to {LOG_PATH}")
    if options.pwned:
        PWNED = True
        PWNED_BANNER = options.pwned
    guest_host = options.host
    if options.nat:
        options.host = "0.0.0.0"
        guest_host = "10.0.2.2"

    http_server(options.host, options.http_port)
    tls_server(options.host, options.tls_port)
    udp_server(options.host, options.udp_port)
    dns_server(options.host, options.dns_port, options.dns_mode, options.dns_answer)

    if options.nat:
        print("\nNAT guest: QEMU user networking maps the host to 10.0.2.2.", flush=True)
        print("Enable NAT (not Isolated) in the VM settings and point the sample at 10.0.2.2.",
              flush=True)
    print(f"\nPoint the samples at {guest_host}:", flush=True)
    print(f"  ./ant-sample-http-beacon --host {guest_host} --port {options.http_port} --rounds 1",
          flush=True)
    print(f"  ./ant-sample-recon       --host {guest_host} --port {options.http_port} --rounds 1",
          flush=True)
    print(f"  ./ant-sample-download      --host {guest_host} --port {options.http_port} --rounds 1",
          flush=True)
    print(f"  ./ant-sample-tls-sni     --host {guest_host} --port {options.tls_port} --rounds 1",
          flush=True)
    print(f"  ./ant-sample-udp-beacon  --host {guest_host} --port {options.udp_port} --rounds 1",
          flush=True)
    print(f"  SAMPLE_DNS_PORT={options.dns_port} ./ant-sample-dns-tunnel --resolver {guest_host} "
          f"--rounds 1", flush=True)
    print("Ctrl-C to stop.\n", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("sink", "stopped")


if __name__ == "__main__":
    main()
