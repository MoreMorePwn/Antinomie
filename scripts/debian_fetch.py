# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Downloads from the Debian archive that survive a slow or failing server.

The bases pin the archive to one snapshot.debian.org date, and snapshot is often
slow (503 "first byte timeout", 504, "No healthy backends", resets mid-file).
A package file has the same pool path on every mirror, so it comes from, in
order: the mirror the user chose, deb.debian.org (a CDN; security packages from
its debian-security tree and security.debian.org), then snapshot.debian.org at
the pinned date. Every file is checked against the SHA-256 and size of the
pinned snapshot's signed index, so no mirror is trusted: a 404 or a mismatch
on one just moves to the next source. The dated index files (InRelease,
Packages.xz, Sources, by-hash) come from snapshot only. Each source gets
ATTEMPTS tries on transient failures (HTTP 5xx and 429, timeouts, resets,
refusals, short bodies) with growing waits, and a partial download resumes with
a Range request where the server supports it. One log line says each retry and
each fallback. Standard library only; this file is self-contained so that
build scripts can load it by path.
"""
import hashlib
import http.client
import http.server
import os
from pathlib import Path
import random
import shutil
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ATTEMPTS = 5
WAITS = (5, 15, 45, 120)
TIMEOUT = 120
DEBIAN = "http://deb.debian.org/debian"
SECURITY = ("http://deb.debian.org/debian-security", "http://security.debian.org/debian-security")
SNAPSHOT = "http://snapshot.debian.org/archive"


class FetchError(RuntimeError):
    """A download that failed on every source."""


class Missing(Exception):
    """The source does not have the file (404, 403, 410): not retried."""


class Mismatch(Exception):
    """The file's size or SHA-256 is not the pinned one."""


def host(url):
    return urllib.parse.urlsplit(url).netloc or url


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _opener(proxy):
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    return urllib.request.build_opener(*handlers)


def _transient(error):
    """Whether a failure is worth another try at the same source."""
    if isinstance(error, urllib.error.HTTPError):
        return error.code >= 500 or error.code in (408, 429)
    return isinstance(error, (OSError, http.client.HTTPException, socket.timeout))


def _describe(error):
    if isinstance(error, urllib.error.HTTPError):
        return str(error.code)
    return type(error).__name__ + (f": {error}" if str(error) else "")


def _download(opener, url, partial, timeout):
    """One try: append to (or start) partial. Raises on a short body."""
    have = partial.stat().st_size if partial.exists() else 0
    request = urllib.request.Request(url)
    if have:
        request.add_header("Range", f"bytes={have}-")
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if error.code == 416 and have:
            # The partial may be complete, or stale: the caller verifies it.
            partial.unlink()
            raise http.client.IncompleteRead(b"", 0) from error
        raise
    with response:
        length = response.headers.get("Content-Length")
        if have and response.status == 206:
            if not response.headers.get("Content-Range", "").startswith(f"bytes {have}-"):
                partial.unlink()
                raise http.client.IncompleteRead(b"", 0)
            mode, total = "ab", have + int(length) if length else None
        else:
            mode, total = "wb", int(length) if length else None
        with partial.open(mode) as output:
            shutil.copyfileobj(response, output, 1 << 20)
    if total is not None and partial.stat().st_size != total:
        raise http.client.IncompleteRead(b"", total - partial.stat().st_size)


def sha1_file(path):
    digest = hashlib.sha1()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_from(url, target, proxy="", sha256=None, size=None, attempts=ATTEMPTS, waits=WAITS,
               log=lambda line: print(line, flush=True), sleep=time.sleep, timeout=TIMEOUT,
               sha1=None):
    """Download url to target (whole or not at all), retrying transient failures.
    Raises Missing, Mismatch, or FetchError (retries used up). sha256, sha1 and
    size, when given, must match."""
    target = Path(target)
    partial = target.with_name(target.name + ".part")
    opener = _opener(proxy)
    name = host(url)
    last = None
    try:
        for attempt in range(1, attempts + 1):
            try:
                _download(opener, url, partial, timeout)
                if (size is not None and partial.stat().st_size != size) or \
                        (sha256 is not None and sha256_file(partial) != sha256) or \
                        (sha1 is not None and sha1_file(partial) != sha1):
                    raise Mismatch(f"{name}: not the pinned file")
                os.replace(partial, target)
                return
            except Mismatch:
                raise
            except Exception as error:
                if isinstance(error, urllib.error.HTTPError):
                    error.close()
                if isinstance(error, urllib.error.HTTPError) and not _transient(error):
                    raise Missing(f"{name}: {error.code}") from error
                if not _transient(error):
                    raise
                last = _describe(error)
                if attempt == attempts:
                    break
                wait = waits[min(attempt - 1, len(waits) - 1)]
                wait += random.uniform(0, wait * 0.2)
                log(f"{name} answered {last}; retrying in {wait:.0f} s "
                    f"(attempt {attempt + 1} of {attempts})")
                sleep(wait)
        raise FetchError(f"{url}: {attempts} attempts failed, last {last}")
    finally:
        if not target.exists() or partial.exists():
            partial.unlink(missing_ok=True)


def fetch_first(urls, target, proxy="", sha256=None, size=None, **options):
    """Download from the first of urls that has the pinned file. Raises FetchError
    naming every URL and what happened when none has."""
    log = options.get("log", lambda line: print(line, flush=True))
    failures = []
    for number, url in enumerate(urls):
        try:
            fetch_from(url, target, proxy, sha256, size, **options)
            return url
        except (Missing, Mismatch, FetchError) as error:
            failures.append(f"{url} ({error})")
            more = number + 1 < len(urls)
            reason = "no such file" if isinstance(error, Missing) \
                else "not the pinned file" if isinstance(error, Mismatch) else "failed"
            if isinstance(error, Missing):
                reason = str(error).rsplit(": ", 1)[-1]
            if more:
                log(f"{host(url)}: {reason}, trying {host(urls[number + 1])}")
    raise FetchError(f"cannot download {Path(target).name}: " + "; ".join(failures))


def fetch(url, target, proxy="", **options):
    """One URL (a dated index file from snapshot), with retries."""
    fetch_first([url], target, proxy, **options)


def valid_mirror(mirror):
    """The mirror's URL without a trailing slash, "" when unset; raises
    ValueError for anything that is not an http(s) URL."""
    mirror = (mirror or "").strip().rstrip("/")
    if mirror and urllib.parse.urlsplit(mirror).scheme not in ("http", "https"):
        raise ValueError(f"the Debian mirror must be an http(s) URL, not {mirror!r}")
    return mirror


def pool_urls(archive, filename, mirror=""):
    """URLs of a pool file, best first: the user's mirror, deb.debian.org (and
    security.debian.org), then the pinned snapshot archive (a URL of the form
    .../archive/debian[-security]/STAMP)."""
    urls = [f"{root}/{filename}" for root in roots(archive, mirror)]
    urls.append(f"{archive.rstrip('/')}/{filename}")
    return list(dict.fromkeys(urls))


def roots(archive, mirror=""):
    """Mirror roots to try before the snapshot, best first (see pool_urls)."""
    security = "/debian-security/" in archive + "/"
    mirror = valid_mirror(mirror)
    found = []
    if mirror:
        found.append(mirror[:-len("/debian")] + "/debian-security" if security
                     and mirror.endswith("/debian") else mirror if not security else None)
    found += list(SECURITY) if security else [DEBIAN]
    return [root for root in found if root]


def index_urls(archive, path, sha256, mirror=""):
    """URLs of a dated index file (path: dists/SUITE/COMPONENT/DIR/NAME), best
    first: the file by its SHA-256 under by-hash on the mirror, deb.debian.org
    (and security.debian.org), then the snapshot's normal path. Mirrors keep
    recent index versions under by-hash; the signed Release names the hash."""
    directory, _, _ = path.rpartition("/")
    urls = [f"{root}/{directory}/by-hash/SHA256/{sha256}" for root in roots(archive, mirror)]
    urls.append(f"{archive.rstrip('/')}/{path}")
    return list(dict.fromkeys(urls))


def release_hashes(text):
    """{path: (SHA256, size)} from the SHA256 list of a (verified) Release text."""
    found, section = {}, None
    for line in text.splitlines():
        if not line.startswith(" "):
            section = line.split(":", 1)[0]
            continue
        fields = line.split()
        if section == "SHA256" and len(fields) == 3:
            found[fields[2]] = (fields[0], int(fields[1]))
    return found


def fetch_index(archive, path, target, sha256, size, mirror="", proxy="", **options):
    """A dated index file named by the signed Release (hash and size), from
    by-hash on the mirrors first, else the snapshot."""
    return fetch_first(index_urls(archive, path, sha256, mirror), target, proxy, sha256, size,
                       **options)


def fetch_pool(archive, filename, target, sha256, size, mirror="", proxy="", **options):
    """A pinned pool file from the mirror order, checked against the signed
    index's SHA-256 and size."""
    return fetch_first(pool_urls(archive, filename, mirror), target, proxy, sha256, size,
                       **options)


def _index_hashes(data):
    """{Filename: (SHA256, size)} from a Packages index (xz, gzip, bz2 or plain)."""
    import bz2
    import gzip
    import lzma
    for magic, unpack in ((b"\xfd7zXZ", lzma.decompress), (b"\x1f\x8b", gzip.decompress),
                          (b"BZh", bz2.decompress)):
        if data.startswith(magic):
            data = unpack(data)
            break
    found = {}
    for stanza in data.decode("utf-8", "replace").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line
                      and not line[0].isspace())
        if "Filename" in fields and "SHA256" in fields:
            found[fields["Filename"]] = (fields["SHA256"], int(fields.get("Size", -1)))
    return found


class PoolProxy:
    """A local HTTP front for the pinned snapshot, for apt (mmdebstrap) to use in
    place of snapshot.debian.org. apt asks for /archive/debian[-security]/STAMP/...:
    dated index files come from snapshot (with retries); pool files come from the
    mirror order, checked against the Packages index apt fetched through here
    (which apt itself checks against the signed InRelease). apt verifies every
    file again, so the result is what a snapshot-only build installs."""

    def __init__(self, mirror="", proxy="", log=lambda line: print(line, flush=True), **options):
        self.mirror, self.proxy, self.log, self.options = valid_mirror(mirror), proxy, log, options
        self.hashes = {}
        self.scratch = Path(tempfile.mkdtemp(prefix="antinomie-fetch-"))
        proxy_ = self
        counter = iter(range(1 << 30))

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                parts = urllib.parse.urlsplit(self.path).path.split("/", 4)
                # ["", "archive", kind, stamp, rest]
                if len(parts) < 5 or parts[1] != "archive" or parts[2] not in (
                        "debian", "debian-security"):
                    return self.send_error(404)
                archive = f"{SNAPSHOT}/{parts[2]}/{parts[3]}"
                rest = parts[4]
                local = proxy_.scratch / str(next(counter))
                try:
                    if rest.startswith("pool/"):
                        known = proxy_.hashes.get((parts[2], rest))
                        fetch_pool(archive, rest, local, known[0] if known else None,
                                   known[1] if known and known[1] >= 0 else None,
                                   proxy_.mirror, proxy_.proxy, log=proxy_.log, **proxy_.options)
                    elif "/by-hash/SHA256/" in rest:
                        directory, _, wanted = rest.partition("/by-hash/SHA256/")
                        urls = [f"{root}/{rest}" for root in roots(archive, proxy_.mirror)]
                        fetch_first(urls + [f"{archive}/{rest}"], local, proxy_.proxy, wanted,
                                    log=proxy_.log, **proxy_.options)
                    else:
                        known = proxy_.hashes.get((parts[2], rest))
                        if known and rest.startswith("dists/"):
                            fetch_index(archive, rest, local, known[0], known[1], proxy_.mirror,
                                        proxy_.proxy, log=proxy_.log, **proxy_.options)
                        else:
                            fetch_first([f"{archive}/{rest}"], local, proxy_.proxy,
                                        log=proxy_.log, **proxy_.options)
                        if rest.startswith("dists/") and rest.endswith("InRelease"):
                            suite = rest.split("/")[1]
                            for name, value in release_hashes(
                                    local.read_text("utf-8", "replace")).items():
                                proxy_.hashes[(parts[2], f"dists/{suite}/{name}")] = value
                        if ("/binary-" in rest and "Packages" in rest) or "/by-hash/" in rest:
                            try:
                                for name, value in _index_hashes(local.read_bytes()).items():
                                    proxy_.hashes[(parts[2], name)] = value
                            except Exception:
                                pass
                except (FetchError, ValueError) as error:
                    proxy_.log(str(error))
                    return self.send_error(502, "upstream failed")
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", str(local.stat().st_size))
                    self.end_headers()
                    with local.open("rb") as source:
                        shutil.copyfileobj(source, self.wfile, 1 << 20)
                finally:
                    local.unlink(missing_ok=True)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True

    @property
    def base(self):
        """The URL that stands for snapshot.debian.org/archive."""
        return f"http://127.0.0.1:{self.server.server_address[1]}/archive"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.scratch, ignore_errors=True)
