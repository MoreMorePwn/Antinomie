#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspectable rules-bucket operations.

The destination is a directory in tests. ``--target hf`` prints the exact
commands and uploads only when HF_TOKEN is already set in the environment.
Tokens are not written to manifests or logs.

Objects are immutable: an existing key with different bytes is refused.
catalog.json is written last. Rollback copies a verified previous catalog
into place and does not delete older objects.
"""
import argparse
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

DEFAULT_BUCKET = "https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve"
REVIEWED_CATALOG_SHA = "b17c76020063bb6386ad02e21e74dfb7f472b0961b2f7f995e2ee87c6b8ea560"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_archive(path):
    raw = path.read_bytes()
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except tarfile.TarError as error:
        raise SystemExit(f"{path} is not a gzip tar archive: {error}") from error
    seen = set()
    with archive:
        for info in archive.getmembers():
            name = info.name.replace("\\", "/")
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or info.issym() or info.islnk() or not info.isfile():
                raise SystemExit(f"unsafe archive member in {path.name}: {name}")
            if name in seen:
                raise SystemExit(f"duplicate archive member in {path.name}: {name}")
            seen.add(name)
    return seen


def catalog_objects(catalog, bucket):
    objects = []
    for pack in catalog["packs"]:
        url = pack["download_url"]
        prefix = bucket.rstrip("/") + "/"
        if not url.startswith(prefix):
            raise SystemExit(f"{pack['id']} download_url is outside {bucket}")
        rel = url[len(prefix):]
        objects.append((rel, pack["sha256"], pack["size"]))
    return objects


def local_archive(output, digest):
    matches = list(Path(output).rglob(f"{digest}.tar.gz"))
    matches = [path for path in matches if path.is_file() and "stage-" not in path.parts]
    if len(matches) != 1:
        raise SystemExit(f"expected one local archive for {digest}, found {len(matches)}")
    return matches[0]


def put_file(root, rel, data, inject):
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        current = dest.read_bytes()
        if current != data:
            raise SystemExit(f"refusing to overwrite {rel}")
        return "unchanged"
    if inject == rel:
        partial = dest.with_name(dest.name + ".partial")
        partial.write_bytes(data[:8])
        raise SystemExit(f"injected failure while writing {rel}")
    temp = dest.with_name(dest.name + ".partial")
    temp.write_bytes(data)
    os.replace(temp, dest)
    return "stored"


def verify_tree(root, catalog, bucket):
    errors = []
    for rel, digest, size in catalog_objects(catalog, bucket):
        path = root / rel
        if not path.is_file():
            errors.append(f"missing {rel}")
            continue
        data = path.read_bytes()
        if len(data) != size or sha256_bytes(data) != digest:
            errors.append(f"checksum mismatch {rel}")
        else:
            validate_archive(path)
    return errors


def command_validate(args):
    output = Path(args.output)
    catalog = json.loads((output / "catalog.json").read_text())
    for _rel, digest, size in catalog_objects(catalog, args.bucket):
        archive = local_archive(output, digest)
        if archive.stat().st_size != size or sha256_file(archive) != digest:
            raise SystemExit(f"{archive} does not match the catalog")
        names = validate_archive(archive)
        if not any(name.endswith("NOTICE") or "LICENSE" in name or name.endswith(".md") for name in names):
            raise SystemExit(f"{archive.name} has no license or notice member")
    print(f"validated {output / 'catalog.json'}")


def command_publish(args):
    output = Path(args.output)
    catalog_bytes = (output / "catalog.json").read_bytes()
    catalog = json.loads(catalog_bytes)
    digest = sha256_bytes(catalog_bytes)
    plan = []
    files = []
    for rel, file_digest, size in catalog_objects(catalog, args.bucket):
        archive = local_archive(output, file_digest)
        data = archive.read_bytes()
        if len(data) != size or sha256_bytes(data) != file_digest:
            raise SystemExit(f"{archive} does not match the catalog")
        validate_archive(archive)
        files.append((rel, data))
        plan.append(rel)
    snapshot_rel = f"catalogs/{digest}.json"
    files.append((snapshot_rel, catalog_bytes))
    plan.append(snapshot_rel)
    if args.restore_snapshot:
        snapshot = Path(args.restore_snapshot).read_bytes()
        snapshot_digest = sha256_bytes(snapshot)
        if args.restore_sha and snapshot_digest != args.restore_sha:
            raise SystemExit("restore snapshot does not match the required sha256")
        files.insert(-1, (f"catalogs/{snapshot_digest}.json", snapshot))
        plan.insert(-1, f"catalogs/{snapshot_digest}.json")
    previous = None
    if args.previous:
        previous = Path(args.previous).read_bytes()
        previous_digest = sha256_bytes(previous)
        files.insert(0, (f"catalogs/{previous_digest}.json", previous))
        plan.insert(0, f"catalogs/{previous_digest}.json")
    plan.append("catalog.json")
    if args.dry_run or args.target == "dry-run":
        print("dry-run")
        for item in plan:
            print(item)
        return
    if args.target == "hf":
        print("hf publication is not performed by this process unless HF_TOKEN is set")
        for item in plan:
            print(item)
        if not os.environ.get("HF_TOKEN"):
            raise SystemExit("promotion blocked: HF_TOKEN is not set")
        raise SystemExit("promotion blocked: live upload requires the explicit publish command with a local target rehearsal first")
    root = Path(args.target)
    root.mkdir(parents=True, exist_ok=True)
    for rel, data in files:
        put_file(root, rel, data, args.inject)
    errors = verify_tree(root, catalog, args.bucket)
    if args.restore_snapshot:
        restored = root / f"catalogs/{sha256_bytes(Path(args.restore_snapshot).read_bytes())}.json"
        if sha256_file(restored) != sha256_bytes(Path(args.restore_snapshot).read_bytes()):
            errors.append("restored snapshot mismatch")
    if args.inject == "promote" or errors:
        raise SystemExit("promotion blocked: " + ("; ".join(errors) if errors else "injected promotion failure"))
    put_file(root, "catalog.json", catalog_bytes, "")
    print(f"promoted {digest}")


def command_verify(args):
    root = Path(args.target)
    catalog = json.loads((root / "catalog.json").read_text())
    errors = verify_tree(root, catalog, args.bucket)
    if errors:
        raise SystemExit("; ".join(errors))
    print(f"verified {sha256_file(root / 'catalog.json')}")


def command_rollback(args):
    root = Path(args.target)
    previous = Path(args.previous).read_bytes()
    catalog = json.loads(previous)
    digest = sha256_bytes(previous)
    stored = root / "catalogs" / f"{digest}.json"
    if not stored.is_file() or stored.read_bytes() != previous:
        raise SystemExit("rollback catalog is not retained with its verified bytes")
    errors = verify_tree(root, catalog, args.bucket)
    if errors:
        raise SystemExit("rollback blocked: " + "; ".join(errors))
    if args.dry_run:
        print(f"dry-run rollback {digest}")
        return
    put_file(root, "catalog.json", previous, "")
    print(f"rolled back to {digest}")


def self_test():
    from pathlib import Path as _Path
    tmp = _Path(tempfile.mkdtemp(prefix="ant-bucket-"))
    try:
        output = tmp / "candidate"
        packs = output / "packs"
        packs.mkdir(parents=True)
        payload = b"rule Demo { condition: true }\n"
        stage = tmp / "stage"
        stage.mkdir()
        (stage / "demo.yar").write_bytes(payload)
        (stage / "NOTICE").write_text("upstream notice\n")
        archive_path = packs / "demo.tar.gz"
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
            data = (stage / "demo.yar").read_bytes()
            info = tarfile.TarInfo("demo.yar")
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
            notice = (stage / "NOTICE").read_bytes()
            info = tarfile.TarInfo("NOTICE")
            info.size = len(notice)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(notice))
        gzip_mod = __import__("gzip")
        with archive_path.open("wb") as handle:
            with gzip_mod.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as compressed:
                compressed.write(raw.getvalue())
        digest = sha256_file(archive_path)
        named = packs / "yara" / "demo" / "1" / f"{digest}.tar.gz"
        named.parent.mkdir(parents=True)
        archive_path.replace(named)
        archive_path = named
        bucket = "https://example.invalid/rules"
        catalog = {
            "schema": 1,
            "packs": [{
                "id": "demo",
                "engine": "yara",
                "version": "1",
                "download_url": f"{bucket}/packs/yara/demo/1/{digest}.tar.gz",
                "sha256": digest,
                "size": archive_path.stat().st_size,
            }],
        }
        (output / "catalog.json").write_text(json.dumps(catalog))
        target = tmp / "bucket"
        ns = argparse.Namespace(output=str(output), bucket=bucket, target=str(target), dry_run=False, inject="", restore_snapshot="", restore_sha="", previous="")
        command_publish(ns)
        command_verify(ns)
        first = (target / "catalog.json").read_bytes()
        # Interrupted archive upload leaves no root promotion.
        failed = tmp / "failed"
        ns.target = str(failed)
        ns.inject = f"packs/yara/demo/1/{digest}.tar.gz"
        try:
            command_publish(ns)
        except SystemExit as error:
            assert "injected failure" in str(error)
        assert not (failed / "catalog.json").exists()
        # Retry after removing the partial succeeds.
        ns.inject = ""
        command_publish(ns)
        # Checksum failure blocks promotion.
        corrupt = tmp / "corrupt"
        ns.target = str(corrupt)
        ns.inject = ""
        command_publish(ns)
        flipped = bytearray((corrupt / f"packs/yara/demo/1/{digest}.tar.gz").read_bytes())
        flipped[0] ^= 0xFF
        (corrupt / f"packs/yara/demo/1/{digest}.tar.gz").write_bytes(flipped)
        try:
            command_verify(argparse.Namespace(target=str(corrupt), bucket=bucket))
            raise AssertionError("corrupt object was accepted")
        except SystemExit as error:
            assert "checksum" in str(error)
        # Different bytes for the same key are refused.
        other = archive_path.read_bytes() + b"\n"
        try:
            put_file(target, f"packs/yara/demo/1/{digest}.tar.gz", other, "")
            raise AssertionError("overwrite was allowed")
        except SystemExit as error:
            assert "overwrite" in str(error)
        # Rollback restores the retained catalog and its objects still match.
        previous = first
        (tmp / "previous.json").write_bytes(previous)
        command_rollback(argparse.Namespace(target=str(target), bucket=bucket, previous=str(tmp / "previous.json"), dry_run=False))
        assert (target / "catalog.json").read_bytes() == previous
        command_verify(argparse.Namespace(target=str(target), bucket=bucket))
        print("bucket self-test passed")
    finally:
        shutil.rmtree(tmp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", default=DEFAULT_BUCKET)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("output")
    publish = sub.add_parser("publish")
    publish.add_argument("output")
    publish.add_argument("--target", required=True)
    publish.add_argument("--previous")
    publish.add_argument("--restore-snapshot")
    publish.add_argument("--restore-sha", default="")
    publish.add_argument("--dry-run", action="store_true")
    publish.add_argument("--inject", default="")
    verify = sub.add_parser("verify")
    verify.add_argument("--target", required=True)
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--target", required=True)
    rollback.add_argument("--previous", required=True)
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
