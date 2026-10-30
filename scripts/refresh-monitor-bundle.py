#!/usr/bin/env python3
"""Publish a new kernel bundle without modifying its source disk or initrd."""
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import argparse
import ctypes
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def helpers():
    spec = importlib.util.spec_from_file_location(
        "debian_image", Path(__file__).with_name("build-debian-image.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact(root, value):
    if not isinstance(value, str):
        raise RuntimeError("bundle artifact must be a path string")
    path = (root / value).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise RuntimeError("bundle artifact must be a regular file inside its directory")
    return path


def publish_new(source, target):
    """Linux no-replace rename keeps publication atomic even with two builders."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                      ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(target))


def refresh(source, kernel, config, output, allow_unversioned=False):
    source = source.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise RuntimeError("output already exists; choose a new unpublished bundle path")
    helper = helpers()
    image = helper.monitor_helpers()
    manifest_path = source / "bundle.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("kernel_version") != "6.12.94" or manifest.get("schema_id") != 1:
        raise RuntimeError("source bundle must use pinned Linux 6.12.94 and schema 1")
    guest = manifest.get("guest")
    console = isinstance(guest, dict) and guest.get("id") == "debian-minimal"
    image.fixed_display_config(config, kernel, modules_ok=console)
    image.stamp_revision({}, kernel, allow_unversioned)
    helper.kernel_release(kernel)
    artifacts = {key: artifact(source, manifest[key])
                 for key in ("kernel", "base_disk")}
    if manifest.get("initrd") is not None:
        artifacts["initrd"] = artifact(source, manifest["initrd"])
    source_hashes = {key: image.checksum(path) for key, path in artifacts.items()}
    # The symbol table belongs to the replaced kernel: part of the source
    # identity, not carried into the refreshed bundle.
    identity_hashes = dict(source_hashes)
    if manifest.get("symbols") is not None:
        identity_hashes["symbols"] = image.checksum(artifact(source, manifest["symbols"]))
    parent_identity = image.bundle_identity(manifest, identity_hashes)
    if manifest.get("base_identity") not in (None, parent_identity):
        raise RuntimeError("installed source base identity mismatch")
    disk = json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", str(artifacts["base_disk"])],
        text=True, timeout=30))
    if disk.get("format") != "qcow2" or disk.get("backing-filename"):
        raise RuntimeError("source base disk must be a standalone qcow2, not an overlay")
    # Original builder manifests carry artifact checksums; installed manifests
    # have a content identity instead, verified again by the normal importer.
    for key, path in artifacts.items():
        expected = manifest.get("sha256", {}).get(manifest[key])
        if expected is not None and source_hashes[key] != expected:
            raise RuntimeError(f"source {key} checksum mismatch")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bundle-refresh-", dir=output.parent) as name:
        staging = Path(name)
        publish = staging / "bundle"
        publish.mkdir()
        mapping = {"kernel": "kernel", "base_disk": "base.qcow2", "initrd": "initrd"}
        for key, path in artifacts.items():
            shutil.copy2(kernel if key == "kernel" else path, publish / mapping[key])
        hashes = {mapping[key]: image.checksum(publish / mapping[key]) for key in artifacts}
        for key in ("base_disk", "initrd"):
            if key in artifacts and hashes[mapping[key]] != source_hashes[key]:
                raise RuntimeError(f"source {key} changed during refresh")
        provenance = publish / "provenance"
        provenance.mkdir()
        shutil.copy2(config, provenance / "kernel.config")
        image.fixed_display_config(provenance / "kernel.config", publish / "kernel",
                                   modules_ok=console)
        build_provenance = {"parent_identity": parent_identity,
            "kernel_sha256": hashes["kernel"], "base_disk_sha256": hashes["base.qcow2"],
            "initrd_sha256": hashes.get("initrd"),
            "kernel_config_sha256": image.checksum(provenance / "kernel.config")}
        record = {"refreshed_at": datetime.now(timezone.utc).isoformat(),
                  "source_manifest_sha256": image.checksum(manifest_path),
                  "source_base_identity": parent_identity,
                  "source_artifact_sha256": source_hashes,
                  "kernel_sha256": hashes["kernel"],
                  "kernel_config_sha256": image.checksum(provenance / "kernel.config"),
                  "fixed_display": True,
                  "preserved": [key for key in ("base_disk", "initrd") if key in artifacts]}
        (provenance / "refresh.json").write_text(json.dumps(record, indent=2) + "\n")
        updated = {key: manifest[key] for key in
                   ("kernel_append", "kernel_version", "schema_id", "guest") if key in manifest}
        updated.update({"format": 1, "kernel": "kernel", "base_disk": "base.qcow2",
                        "initrd": "initrd" if "initrd" in artifacts else None,
                        "fixed_display": True, "sha256": hashes,
                        "build_provenance": build_provenance})
        # The kept disk and initrd decide the root buses and DHCP; the new
        # kernel decides UEFI and which controllers are built in.
        kept = manifest.get("stealth_support") or []
        support = image.stealth_support(config, publish / "kernel",
                                        root_buses="sata" in kept or "nvme" in kept,
                                        dhcp="dhcp" in kept, module_buses=console)
        # Interface naming is a property of the preserved root filesystem.
        if "onboardnic" in kept:
            support.append("onboardnic")
        if support:
            updated["stealth_support"] = support
        image.stamp_revision(updated, publish / "kernel", allow_unversioned)
        (publish / "bundle.json").write_text(json.dumps(updated, indent=2) + "\n")
        for path in publish.rglob("*"):
            if path.is_file():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        for path in (provenance, publish):
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        publish_new(publish, output)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-unversioned", action="store_true",
                        help="accept a development kernel without a source id")
    args = parser.parse_args()
    try:
        print(refresh(args.source, args.kernel, args.kernel_config, args.output,
                      args.allow_unversioned))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, "bundle refresh failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
