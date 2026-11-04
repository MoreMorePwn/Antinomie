#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Tests for scripts/debian_fetch.py against a local HTTP server (no network)."""
import hashlib
import http.server
import importlib.util
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.request

spec = importlib.util.spec_from_file_location(
    "debian_fetch", Path(__file__).resolve().with_name("debian_fetch.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

BODY = bytes(range(256)) * 4096          # 1 MiB
SHA = hashlib.sha256(BODY).hexdigest()


class Server:
    """script: {path: [behaviour, ...]} consumed one per request; the last one
    repeats. Behaviours: an int (HTTP status), "ok", "wrong" (other bytes),
    ("cut", n) (promise the whole body, send n bytes, close)."""

    def __init__(self, script):
        self.script, self.requests = script, []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                owner.requests.append((self.path, self.headers.get("Range")))
                steps = owner.script.get(self.path, [404])
                step = steps.pop(0) if len(steps) > 1 else steps[0]
                if isinstance(step, int):
                    self.send_response(step)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if isinstance(step, bytes):
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(step)))
                    self.end_headers()
                    self.wfile.write(step)
                    return
                body = BODY[::-1] if step == "wrong" else BODY
                start, status = 0, 200
                if self.headers.get("Range") and step == "ok":
                    start, status = int(self.headers["Range"][6:].split("-")[0]), 206
                self.send_response(status)
                self.send_header("Content-Length", str(len(body) - start))
                if status == 206:
                    self.send_header("Content-Range",
                                     f"bytes {start}-{len(body) - 1}/{len(body)}")
                self.end_headers()
                if isinstance(step, tuple):
                    self.wfile.write(body[:step[1]])
                    self.wfile.flush()
                    self.close_connection = True
                    return
                self.wfile.write(body[start:])

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.target = Path(self.directory.name) / "file.deb"
        self.log, self.waits = [], []
        self.options = {"log": self.log.append, "sleep": self.waits.append}
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.close()
        self.directory.cleanup()

    def serve(self, script):
        server = Server(script)
        self.servers.append(server)
        return server

    def test_503_twice_then_200(self):
        server = self.serve({"/f": [503, 503, "ok"]})
        fetch.fetch_first([server.url + "/f"], self.target, sha256=SHA, size=len(BODY),
                          **self.options)
        self.assertEqual(self.target.read_bytes(), BODY)
        self.assertEqual(len(server.requests), 3)
        self.assertEqual(len(self.waits), 2)
        self.assertTrue(5 <= self.waits[0] <= 6 and 15 <= self.waits[1] <= 18)
        self.assertIn("answered 503; retrying in", self.log[0])
        self.assertIn("(attempt 2 of 5)", self.log[0])
        self.assertIn("(attempt 3 of 5)", self.log[1])
        self.assertFalse(self.target.with_name("file.deb.part").exists())

    def test_404_on_the_mirror_then_snapshot(self):
        mirror, snapshot = self.serve({"/f": [404]}), self.serve({"/f": ["ok"]})
        used = fetch.fetch_first([mirror.url + "/f", snapshot.url + "/f"], self.target,
                                 sha256=SHA, size=len(BODY), **self.options)
        self.assertEqual(used, snapshot.url + "/f")
        self.assertEqual(len(mirror.requests), 1)      # 404 is not retried
        self.assertEqual(self.waits, [])
        self.assertIn("404, trying 127.0.0.1", self.log[0])

    def test_sha256_mismatch_on_the_mirror_then_snapshot_good(self):
        mirror, snapshot = self.serve({"/f": ["wrong"]}), self.serve({"/f": ["ok"]})
        fetch.fetch_first([mirror.url + "/f", snapshot.url + "/f"], self.target, sha256=SHA,
                          size=len(BODY), **self.options)
        self.assertEqual(self.target.read_bytes(), BODY)
        self.assertIn("not the pinned file, trying", self.log[0])

    def test_always_503_fails_naming_the_attempts(self):
        mirror, snapshot = self.serve({"/f": [404]}), self.serve({"/f": [503]})
        with self.assertRaises(fetch.FetchError) as caught:
            fetch.fetch_first([mirror.url + "/f", snapshot.url + "/f"], self.target,
                              sha256=SHA, **self.options)
        text = str(caught.exception)
        self.assertIn(mirror.url + "/f", text)
        self.assertIn(snapshot.url + "/f", text)
        self.assertIn("5 attempts failed, last 503", text)
        self.assertEqual(len(snapshot.requests), 5)
        self.assertEqual(len(self.waits), 4)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.target.with_name("file.deb.part").exists())

    def test_reset_mid_body_then_range_resume(self):
        server = self.serve({"/f": [("cut", 300000), "ok"]})
        fetch.fetch_first([server.url + "/f"], self.target, sha256=SHA, size=len(BODY),
                          **self.options)
        self.assertEqual(self.target.read_bytes(), BODY)
        self.assertEqual(server.requests[0][1], None)
        self.assertEqual(server.requests[1][1], "bytes=300000-")
        self.assertIn("retrying in", self.log[0])

    def index_fixture(self, mirror_step):
        path = "dists/trixie/main/binary-arm64/Packages.xz"
        snapshot = self.serve({"/archive/debian/S/" + path: ["ok"]})
        mirror = self.serve({f"/dists/trixie/main/binary-arm64/by-hash/SHA256/{SHA}": [mirror_step]})
        self.addCleanup(setattr, fetch, "DEBIAN", fetch.DEBIAN)
        fetch.DEBIAN = mirror.url
        archive = snapshot.url + "/archive/debian/S"
        fetch.fetch_index(archive, path, self.target, SHA, len(BODY), **self.options)
        self.assertEqual(self.target.read_bytes(), BODY)
        self.assertEqual(len(mirror.requests), 1)
        self.assertEqual(len(snapshot.requests), 1)
        return mirror

    def test_index_by_hash_404_then_snapshot(self):
        self.index_fixture(404)
        self.assertIn("404, trying 127.0.0.1", self.log[0])

    def test_index_by_hash_mismatch_then_snapshot(self):
        self.index_fixture("wrong")
        self.assertIn("not the pinned file, trying", self.log[0])

    def test_index_urls_by_hash_first_snapshot_last(self):
        archive = "https://snapshot.debian.org/archive/debian/S"
        urls = fetch.index_urls(archive, "dists/trixie/main/binary-arm64/Packages.xz", "ab",
                                "http://ftp.de.debian.org/debian")
        self.assertEqual(urls, [
            "http://ftp.de.debian.org/debian/dists/trixie/main/binary-arm64/by-hash/SHA256/ab",
            "http://deb.debian.org/debian/dists/trixie/main/binary-arm64/by-hash/SHA256/ab",
            archive + "/dists/trixie/main/binary-arm64/Packages.xz"])

    def test_pool_order_and_mirror_validation(self):
        archive = "https://snapshot.debian.org/archive/debian/20261020T213255Z"
        self.assertEqual(fetch.pool_urls(archive, "pool/main/b/bc/bc.deb"), [
            "http://deb.debian.org/debian/pool/main/b/bc/bc.deb",
            archive + "/pool/main/b/bc/bc.deb"])
        urls = fetch.pool_urls(archive, "pool/main/b/bc/bc.deb", "http://ftp.de.debian.org/debian/")
        self.assertEqual(urls[0], "http://ftp.de.debian.org/debian/pool/main/b/bc/bc.deb")
        security = fetch.pool_urls(archive.replace("/debian/", "/debian-security/"),
                                   "pool/updates/main/l/linux/x.deb", "http://ftp.de.debian.org/debian")
        self.assertEqual(security[0], "http://ftp.de.debian.org/debian-security/pool/updates/main/l/linux/x.deb")
        self.assertEqual(security[1:3], [f"{root}/pool/updates/main/l/linux/x.deb"
                                         for root in fetch.SECURITY])
        self.assertTrue(security[-1].startswith("https://snapshot.debian.org/archive/debian-security/"))
        with self.assertRaises(ValueError):
            fetch.valid_mirror("ftp://ftp.de.debian.org/debian")

    def test_proxy_front_serves_pool_files_checked_against_the_index(self):
        # apt asks the front for the snapshot's index, then for a pool file. The
        # mirror has other bytes there and deb.debian.org (a local stand-in) has
        # none: the front takes the snapshot's copy, the one the index names.
        index = ("Package: p\nFilename: pool/main/p/p/p.deb\nSize: %d\nSHA256: %s\n\n"
                 % (len(BODY), SHA)).encode()
        snapshot = self.serve({"/archive/debian/S/dists/trixie/main/binary-amd64/Packages": [index],
                               "/archive/debian/S/pool/main/p/p/p.deb": ["ok"]})
        mirror = self.serve({"/pool/main/p/p/p.deb": ["wrong"]})
        cdn = self.serve({"/pool/main/p/p/p.deb": [404]})
        for name, value in (("SNAPSHOT", snapshot.url + "/archive"), ("DEBIAN", cdn.url)):
            self.addCleanup(setattr, fetch, name, getattr(fetch, name))
            setattr(fetch, name, value)
        with fetch.PoolProxy(mirror.url, log=self.log.append) as front:
            got = urllib.request.urlopen(
                front.base + "/debian/S/dists/trixie/main/binary-amd64/Packages").read()
            self.assertEqual(got, index)
            body = urllib.request.urlopen(front.base + "/debian/S/pool/main/p/p/p.deb").read()
        self.assertEqual(body, BODY)
        self.assertEqual(len(mirror.requests), 1)
        self.assertEqual(len(cdn.requests), 1)
        self.assertTrue(any("not the pinned file, trying" in line for line in self.log))


if __name__ == "__main__":
    unittest.main()
