#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inspectable rules-bucket operations.

A store is either a local directory (tests and rehearsals) or the Hugging Face
Storage Bucket (``--target hf``). The bucket is written with ``hf buckets cp``
under the existing CLI login; this script never reads, passes or prints a
token. Reads use the public HTTPS resolve URL, so verification is anonymous.

Pack archives and ``catalogs/<sha256>.json`` snapshots are immutable: the same
bytes at an existing key are left alone and different bytes are refused.
``catalog.json`` is the only mutable key. It is replaced last, and only after
every archive it references and its own snapshot verify in the store. The
catalog it replaces is kept as a snapshot first, so rollback is a promotion
of a retained snapshot whose objects still verify. ``--expect-current``
refuses to replace a root that changed since the publisher looked at it.

There is no transaction across objects. A failure before promotion leaves
the previous root usable; running the same command again resumes, because
objects already stored with the right bytes are skipped.
"""
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_BUCKET = "https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve"
DEFAULT_BUCKET_ID = "MoreMorePwn/antinomie-rules"
ROOT = "catalog.json"
# Largest object a read accepts, in octets.
READ_LIMIT = 256 * 1024 * 1024


class Refused(SystemExit):
    """An operation that must not happen, such as overwriting an immutable key."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_key(digest):
    return f"catalogs/{digest}.json"


def validate_archive(name, raw):
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except tarfile.TarError as error:
        raise SystemExit(f"{name} is not a gzip tar archive: {error}") from error
    seen = set()
    with archive:
        for info in archive.getmembers():
            member = info.name.replace("\\", "/")
            parts = Path(member).parts
            if member.startswith("/") or ".." in parts or info.issym() or info.islnk() or not info.isfile():
                raise SystemExit(f"unsafe archive member in {name}: {member}")
            if member in seen:
                raise SystemExit(f"duplicate archive member in {name}: {member}")
            seen.add(member)
    return seen


def catalog_objects(catalog, bucket):
    """Archives a catalog references in the bucket. Schema 2 lists upstream
    sources, not hosted archives, so the bucket holds only the catalog."""
    objects = []
    if catalog.get("schema") == 2:
        for pack in catalog["packs"]:
            for source in pack["sources"]:
                if not source["url"].startswith("https://") or any(
                    not file["sha256"] or len(file["sha256"]) != 64 for file in source["files"]
                ):
                    raise SystemExit(f"{pack['id']} has a source without an https URL or file hashes")
        return objects
    for pack in catalog["packs"]:
        url = pack["download_url"]
        prefix = bucket.rstrip("/") + "/"
        if not url.startswith(prefix):
            raise SystemExit(f"{pack['id']} download_url is outside {bucket}")
        rel = url[len(prefix):]
        if rel == ROOT or rel.startswith("catalogs/") or ".." in Path(rel).parts:
            raise SystemExit(f"{pack['id']} download_url names a reserved key: {rel}")
        objects.append((rel, pack["sha256"], pack["size"]))
    return objects


def local_archive(output, digest):
    matches = list(Path(output).rglob(f"{digest}.tar.gz"))
    matches = [path for path in matches if path.is_file() and "stage-" not in path.parts]
    if len(matches) != 1:
        raise SystemExit(f"expected one local archive for {digest}, found {len(matches)}")
    return matches[0]


class LocalStore:
    """A directory laid out like the bucket. ``inject`` names a key whose write
    fails after a partial file, or ``promote`` to fail the root replacement."""

    def __init__(self, root, inject=""):
        self.root = Path(root)
        self.inject = inject

    def describe(self):
        return str(self.root)

    def read(self, rel):
        path = self.root / rel
        return path.read_bytes() if path.is_file() else None

    def write(self, rel, data):
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        temp = dest.with_name(dest.name + ".partial")
        if self.inject == rel or (rel == ROOT and self.inject == "promote"):
            temp.write_bytes(data[: len(data) // 2])
            raise SystemExit(f"injected failure while writing {rel}")
        temp.write_bytes(data)
        os.replace(temp, dest)


class HfStore:
    """The Storage Bucket. Writes go through ``hf buckets cp``; reads are
    anonymous HTTPS requests to the public resolve URL."""

    def __init__(self, bucket_id, base):
        self.bucket_id = bucket_id
        self.base = base.rstrip("/")

    def describe(self):
        return f"hf://buckets/{self.bucket_id}"

    def read(self, rel):
        request = urllib.request.Request(
            f"{self.base}/{rel}", headers={"Cache-Control": "no-cache"}
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data = response.read(READ_LIMIT + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise SystemExit(f"reading {rel}: HTTP {error.code}") from error
        if len(data) > READ_LIMIT:
            raise SystemExit(f"reading {rel}: larger than the read limit")
        return data

    def write(self, rel, data):
        with tempfile.TemporaryDirectory(prefix="ant-publish-") as scratch:
            source = Path(scratch) / Path(rel).name
            source.write_bytes(data)
            result = subprocess.run(
                ["hf", "buckets", "cp", str(source), f"hf://buckets/{self.bucket_id}/{rel}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1800,
                check=False,
            )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["no output"]
            raise SystemExit(f"hf buckets cp {rel} failed: {detail[0]}")


def make_store(args):
    if args.target == "hf":
        return HfStore(args.bucket_id, args.bucket)
    return LocalStore(args.target, getattr(args, "inject", ""))


def put_object(store, rel, data, receipts):
    """Store an immutable key. The same bytes are left alone; others are refused."""
    current = store.read(rel)
    if current is not None:
        if current != data:
            raise Refused(f"refusing to overwrite immutable {rel}")
        receipts.append(f"unchanged {rel}")
        return
    store.write(rel, data)
    receipts.append(f"stored {rel}")


def verify_catalog(store, catalog_bytes, bucket):
    """Every archive the catalog references and its snapshot, read back from the store."""
    catalog = json.loads(catalog_bytes)
    digest = sha256_bytes(catalog_bytes)
    errors = []
    for rel, sha, size in catalog_objects(catalog, bucket):
        data = store.read(rel)
        if data is None:
            errors.append(f"missing {rel}")
        elif len(data) != size or sha256_bytes(data) != sha:
            errors.append(f"checksum mismatch {rel}")
        else:
            validate_archive(rel, data)
    snapshot = store.read(snapshot_key(digest))
    if snapshot != catalog_bytes:
        errors.append(f"snapshot {snapshot_key(digest)} is {'missing' if snapshot is None else 'different'}")
    return errors


def promote(store, catalog_bytes, bucket, expect_current, receipts):
    """Replace the root with ``catalog_bytes`` after its objects verify.

    The current root is kept as a snapshot first. With ``expect_current`` the
    root must still have that SHA-256; ``none`` means no root may exist yet.
    """
    digest = sha256_bytes(catalog_bytes)
    current = store.read(ROOT)
    current_digest = sha256_bytes(current) if current is not None else "none"
    if expect_current and expect_current != current_digest:
        raise Refused(
            f"refusing to replace {ROOT}: it is {current_digest}, not the expected {expect_current}"
        )
    if current is not None:
        put_object(store, snapshot_key(current_digest), current, receipts)
    errors = verify_catalog(store, catalog_bytes, bucket)
    if errors:
        raise SystemExit("promotion blocked: " + "; ".join(errors))
    if current == catalog_bytes:
        receipts.append(f"unchanged {ROOT} {digest}")
        return
    store.write(ROOT, catalog_bytes)
    if store.read(ROOT) != catalog_bytes:
        raise SystemExit(f"{ROOT} did not read back as {digest}; the previous root was {current_digest}")
    receipts.append(f"promoted {ROOT} {current_digest} -> {digest}")


def candidate_files(output, bucket):
    catalog_bytes = (Path(output) / ROOT).read_bytes()
    catalog = json.loads(catalog_bytes)
    files = []
    for rel, digest, size in catalog_objects(catalog, bucket):
        archive = local_archive(output, digest)
        data = archive.read_bytes()
        if len(data) != size or sha256_bytes(data) != digest:
            raise SystemExit(f"{archive} does not match the catalog")
        validate_archive(archive.name, data)
        files.append((rel, data))
    return catalog_bytes, files


def command_validate(args):
    output = Path(args.output)
    catalog = json.loads((output / ROOT).read_text())
    for _rel, digest, size in catalog_objects(catalog, args.bucket):
        archive = local_archive(output, digest)
        if archive.stat().st_size != size or sha256_file(archive) != digest:
            raise SystemExit(f"{archive} does not match the catalog")
        names = validate_archive(archive.name, archive.read_bytes())
        if not any(name.endswith("NOTICE") or "LICENSE" in name or name.endswith(".md") for name in names):
            raise SystemExit(f"{archive.name} has no license or notice member")
    print(f"validated {output / ROOT}")


def command_publish(args):
    catalog_bytes, files = candidate_files(args.output, args.bucket)
    digest = sha256_bytes(catalog_bytes)
    store = make_store(args)
    if args.dry_run:
        print(f"dry-run publish {digest} to {store.describe()}")
        for rel, _data in files:
            print(f"object {rel}")
        print(f"object {snapshot_key(digest)}")
        print(f"root {ROOT} (expect {args.expect_current or 'any'})")
        return []
    receipts = []
    for rel, data in files:
        put_object(store, rel, data, receipts)
    put_object(store, snapshot_key(digest), catalog_bytes, receipts)
    promote(store, catalog_bytes, args.bucket, args.expect_current, receipts)
    for line in receipts:
        print(line)
    return receipts


def command_verify(args):
    store = make_store(args)
    root = store.read(ROOT)
    if root is None:
        raise SystemExit(f"{store.describe()} has no {ROOT}")
    errors = verify_catalog(store, root, args.bucket)
    if errors:
        raise SystemExit("; ".join(errors))
    print(f"verified {sha256_bytes(root)}")


def command_rollback(args):
    store = make_store(args)
    if args.previous:
        previous = Path(args.previous).read_bytes()
        if args.to and sha256_bytes(previous) != args.to:
            raise SystemExit("--previous does not have the --to SHA-256")
        digest = sha256_bytes(previous)
    elif args.to:
        digest = args.to
        previous = None
    else:
        raise SystemExit("rollback needs --to SHA256 or --previous FILE")
    retained = store.read(snapshot_key(digest))
    if retained is None or sha256_bytes(retained) != digest:
        raise SystemExit(f"rollback catalog {digest} is not retained with its verified bytes")
    if previous is not None and retained != previous:
        raise SystemExit("the retained snapshot differs from --previous")
    if args.dry_run:
        errors = verify_catalog(store, retained, args.bucket)
        print(f"dry-run rollback to {digest}: " + ("; ".join(errors) if errors else "objects verify"))
        return []
    receipts = []
    promote(store, retained, args.bucket, args.expect_current, receipts)
    for line in receipts:
        print(line)
    return receipts


def build_candidate(output, bucket, packs):
    """A candidate directory with one deterministic archive per (id, rules) pair."""
    import gzip

    catalog = {"schema": 1, "packs": []}
    for pack_id, rules in packs:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name, data in ((f"{pack_id}.yar", rules), ("NOTICE", b"upstream notice\n")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
        packed = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=packed, mtime=0) as compressed:
            compressed.write(raw.getvalue())
        data = packed.getvalue()
        digest = sha256_bytes(data)
        rel = f"packs/yara/{pack_id}/1/{digest}.tar.gz"
        path = Path(output) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        catalog["packs"].append({
            "id": pack_id,
            "engine": "yara",
            "version": "1",
            "download_url": f"{bucket}/{rel}",
            "sha256": digest,
            "size": len(data),
        })
    (Path(output) / ROOT).write_text(json.dumps(catalog, sort_keys=True))
    return (Path(output) / ROOT).read_bytes()


def expect_exit(text, action):
    try:
        action()
    except SystemExit as error:
        assert text in str(error), f"{text!r} not in {error}"
        return
    raise AssertionError(f"expected failure containing {text!r}")


def self_test():
    tmp = Path(tempfile.mkdtemp(prefix="ant-bucket-"))
    bucket = "https://example.invalid/rules"
    try:
        first = tmp / "a"
        second = tmp / "b"
        a = build_candidate(first, bucket, [("demo", b"rule Demo { condition: true }\n")])
        b = build_candidate(second, bucket, [
            ("demo", b"rule Demo { condition: true }\n"),
            ("more", b"rule More { condition: true }\n"),
        ])
        a_sha, b_sha = sha256_bytes(a), sha256_bytes(b)
        target = tmp / "bucket"

        def publish(output, expect="", inject="", dry_run=False):
            return command_publish(argparse.Namespace(
                output=str(output), bucket=bucket, target=str(target), bucket_id="",
                expect_current=expect, inject=inject, dry_run=dry_run))

        def rollback(to, expect="", inject=""):
            return command_rollback(argparse.Namespace(
                bucket=bucket, target=str(target), bucket_id="", to=to, previous="",
                expect_current=expect, inject=inject, dry_run=False))

        def verify():
            command_verify(argparse.Namespace(target=str(target), bucket=bucket, bucket_id=""))

        def root():
            return (target / ROOT).read_bytes()

        publish(first, dry_run=True)
        assert not target.exists(), "dry run wrote to the target"
        # An interrupted archive upload leaves no root; the retry resumes.
        archive_rel = json.loads(a)["packs"][0]["download_url"][len(bucket) + 1:]
        expect_exit("injected failure", lambda: publish(first, inject=archive_rel))
        assert not (target / ROOT).exists()
        receipts = publish(first, expect="none")
        assert f"promoted {ROOT} none -> {a_sha}" in receipts, receipts
        verify()
        # Repeating the same publication is harmless.
        assert f"unchanged {ROOT} {a_sha}" in publish(first)
        # A changed root replaces A and retains it as a snapshot.
        expect_exit("injected failure", lambda: publish(second, inject=snapshot_key(b_sha)))
        assert root() == a
        expect_exit("injected failure", lambda: publish(second, inject="promote"))
        assert root() == a, "an interrupted promotion changed the root"
        assert f"promoted {ROOT} {a_sha} -> {b_sha}" in publish(second, expect=a_sha)
        assert root() == b and (target / snapshot_key(a_sha)).read_bytes() == a
        verify()
        # A publisher that looked before B landed is refused.
        expect_exit("not the expected", lambda: publish(first, expect=a_sha))
        assert root() == b
        # Real rollback to different, older bytes, then forward again.
        assert f"promoted {ROOT} {b_sha} -> {a_sha}" in rollback(a_sha, expect=b_sha)
        assert root() == a
        verify()
        assert f"unchanged {ROOT} {a_sha}" in rollback(a_sha)
        assert f"promoted {ROOT} {a_sha} -> {b_sha}" in rollback(b_sha)
        expect_exit("not retained", lambda: rollback("0" * 64))
        # A corrupt object blocks promotion and the root stays usable.
        stored = target / archive_rel
        good = stored.read_bytes()
        stored.write_bytes(good[:-1] + bytes([good[-1] ^ 0xFF]))
        expect_exit("checksum mismatch", lambda: rollback(a_sha))
        assert root() == b
        expect_exit("checksum mismatch", verify)
        stored.write_bytes(good)
        verify()
        # Immutable keys still refuse different bytes.
        expect_exit("refusing to overwrite immutable", lambda: put_object(
            LocalStore(target), archive_rel, good + b"\n", []))
        expect_exit("refusing to overwrite immutable", lambda: put_object(
            LocalStore(target), snapshot_key(a_sha), b"{}", []))
        # Schema 2 catalogs list upstream sources: only the catalog is stored.
        third = tmp / "c"
        third.mkdir()
        sources = {"schema": 2, "packs": [{"id": "demo", "sources": [{
            "url": "https://example.invalid/demo.yar",
            "files": [{"path": "demo.yar", "sha256": "0" * 64}]}]}]}
        c = json.dumps(sources, sort_keys=True).encode()
        (third / ROOT).write_bytes(c)
        assert f"promoted {ROOT} {b_sha} -> {sha256_bytes(c)}" in publish(third, expect=b_sha)
        verify()
        sources["packs"][0]["sources"][0]["files"][0]["sha256"] = ""
        (third / ROOT).write_text(json.dumps(sources))
        expect_exit("without an https URL or file hashes", lambda: publish(third))
        print("bucket self-test passed")
    finally:
        shutil.rmtree(tmp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", default=DEFAULT_BUCKET, help="public resolve URL prefix")
    parser.add_argument("--bucket-id", default=DEFAULT_BUCKET_ID, help="namespace/name for hf targets")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("output")
    publish = sub.add_parser("publish")
    publish.add_argument("output")
    publish.add_argument("--target", required=True, help="a directory, or hf")
    publish.add_argument("--expect-current", default="", help="SHA-256 of the root to replace, or none")
    publish.add_argument("--dry-run", action="store_true")
    publish.add_argument("--inject", default="", help=argparse.SUPPRESS)
    verify = sub.add_parser("verify")
    verify.add_argument("--target", required=True, help="a directory, or hf")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--target", required=True, help="a directory, or hf")
    rollback.add_argument("--to", default="", help="SHA-256 of a retained catalog snapshot")
    rollback.add_argument("--previous", default="", help="local copy of the catalog to restore")
    rollback.add_argument("--expect-current", default="", help="SHA-256 of the root to replace")
    rollback.add_argument("--dry-run", action="store_true")
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "validate":
        command_validate(args)
    elif args.command == "publish":
        command_publish(args)
    elif args.command == "verify":
        command_verify(args)
    elif args.command == "rollback":
        command_rollback(args)
    elif args.command == "self-test":
        self_test()


if __name__ == "__main__":
    main()
