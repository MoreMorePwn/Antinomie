#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the public Antinomie rules catalog from pinned community sources.

The monitor downloads the archives this script writes. It does not clone
upstream repositories or rebuild collections during a scan.

Usage:
  prepare-catalog.py OUTPUT_DIR \
    --yara PATH --yara-release 20261004 \
    --ids PATH --ids-url URL \
    --sigma DIR --sigma-commit COMMIT
"""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path

BUCKET = "https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve"

SIGMA_CATEGORIES = {
    "process_creation",
    "file_event",
    "file_delete",
    "file_rename",
    "file_access",
    "dns_query",
    "http_request",
    "antinomie_bpf",
    "antinomie_file_metadata",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_tar(directory, destination):
    files = sorted(path for path in directory.rglob("*") if path.is_file() and not path.is_symlink())
    with tarfile.open(destination, "w:gz") as archive:
        for path in files:
            data = path.read_bytes()
            info = tarfile.TarInfo(str(path.relative_to(directory)).replace("\\", "/"))
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            archive.addfile(info, io.BytesIO(data))


def yara_counts(text):
    rules = helpers = 0
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("private rule ") or stripped.startswith("private global rule "):
            helpers += 1
            rules += 1
        elif stripped.startswith("rule ") or stripped.startswith("global rule "):
            rules += 1
    return rules - helpers, helpers


def field(text, key):
    prefix = key + ":"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix):].strip().strip("'\"")
    return ""


def prepare_sigma(source, dest):
    kept = excluded = 0
    reasons = []
    rules = dest / "rules"
    rules.mkdir(parents=True)
    for path in sorted(source.rglob("*.yml")):
        text = path.read_text(errors="replace")
        product = field(text, "product")
        category = field(text, "category")
        if product and product != "linux":
            excluded += 1
            reasons.append(f"{path.name}: product {product} is not a captured Linux event")
        elif category not in SIGMA_CATEGORIES:
            excluded += 1
            reasons.append(f"{path.name}: category {category or 'missing'} is not a captured event category")
        else:
            kept += 1
        target = rules / path.name
        if target.exists():
            target = rules / f"{path.parent.name}-{path.name}"
        target.write_text(text)
    (dest / "excluded.txt").write_text("\n".join(reasons) + ("\n" if reasons else ""))
    license_path = source.parents[1] / "LICENSE"
    if license_path.is_file():
        (dest / "LICENSE").write_text(license_path.read_text())
    return kept, excluded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--yara", required=True)
    parser.add_argument("--yara-release", required=True)
    parser.add_argument("--ids", required=True)
    parser.add_argument("--ids-url", required=True)
    parser.add_argument("--sigma", required=True)
    parser.add_argument("--sigma-commit", required=True)
    parser.add_argument("--pack-revision", default="", help="Suffix for a rebuilt archive that must not reuse an older version id")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    packs = output / "packs"
    packs.mkdir(exist_ok=True)

    yara_src = Path(args.yara)
    yara_dir = output / "stage-yara"
    if yara_dir.exists():
        import shutil
        shutil.rmtree(yara_dir)
    yara_dir.mkdir()
    text = yara_src.read_text()
    (yara_dir / "yara-forge-core.yar").write_text(text)
    (yara_dir / "NOTICE").write_text(
        "Redistributable subset of YARA-Forge core "
        f"{args.yara_release}. Each rule keeps its author, license and source_url. "
        "Rules whose license does not allow redistribution, and rules that do not "
        "compile with YARA-X 1.21, are absent. This file is not MIT.\n"
    )
    normal, helpers = yara_counts(text)
    yara_archive = packs / f"yara-forge-core-{args.yara_release}.tar.gz"
    write_tar(yara_dir, yara_archive)

    ids_dir = output / "stage-ids"
    if ids_dir.exists():
        import shutil
        shutil.rmtree(ids_dir)
    ids_dir.mkdir()
    with tarfile.open(args.ids, "r:gz") as archive:
        archive.extractall(ids_dir, filter="data")
    ids_rules = 0
    for path in ids_dir.rglob("*.rules"):
        ids_rules += sum(1 for line in path.read_text(errors="replace").splitlines() if "sid:" in line and not line.lstrip().startswith("#"))
    ids_archive = packs / "emerging-threats-open.tar.gz"
    write_tar(ids_dir, ids_archive)

    sigma_dir = output / "stage-sigma"
    if sigma_dir.exists():
        import shutil
        shutil.rmtree(sigma_dir)
    kept, excluded = prepare_sigma(Path(args.sigma), sigma_dir)
    sigma_archive = packs / f"sigmahq-linux-{args.sigma_commit[:12]}.tar.gz"
    write_tar(sigma_dir, sigma_archive)

    def version_of(upstream):
        revision = args.pack_revision.strip()
        return f"{upstream}-{revision}" if revision else upstream

    def entry(archive, **fields):
        return {
            "id": fields["id"],
            "engine": fields["engine"],
            "name": fields["name"],
            "version": fields["version"],
            "upstream_revision": fields["upstream_revision"],
            "upstream_url": fields["upstream_url"],
            "download_url": f"{BUCKET}/packs/{fields['engine']}/{fields['id']}/{fields['version']}/{sha256(archive)}.tar.gz",
            "sha256": sha256(archive),
            "size": archive.stat().st_size,
            "app": ">=0.6.2",
            "engine_requirement": fields["engine_requirement"],
            "rules": fields["rules"],
            "helpers": fields["helpers"],
            "license": fields["license"],
            "evidence": fields["evidence"],
            "limits": fields["limits"],
        }

    catalog = {
        "schema": 1,
        "packs": [
            entry(
                yara_archive,
                id="yara-forge-core",
                engine="yara",
                name="YARA-Forge Core",
                version=version_of(args.yara_release),
                upstream_revision=args.yara_release,
                upstream_url="https://github.com/YARAHQ/yara-forge",
                engine_requirement="YARA-X 1.21",
                rules=normal,
                helpers=helpers,
                license="Per-rule licenses in the rule metadata. See NOTICE. Not one MIT license.",
                evidence=["sample", "memory", "recovered-file"],
                limits=["Redistributable subset only. Non-redistributable and non-compiling rules are excluded."],
            ),
            entry(
                ids_archive,
                id="emerging-threats-open",
                engine="ids",
                name="Emerging Threats Open",
                version=version_of(sha256(Path(args.ids))[:12]),
                upstream_revision=sha256(Path(args.ids)),
                upstream_url=args.ids_url,
                engine_requirement="Suricata 7",
                rules=ids_rules,
                helpers=0,
                license="Mixed: GPLv2 for some SID ranges and BSD for Emerging Threats rules. See LICENSE in the pack. Not MIT.",
                evidence=["pcap"],
                limits=[
                    "Rules that require an external dataset or a TLS fingerprint keyword are reported and not loaded.",
                    "Duplicate SIDs keep the first copy.",
                    "VM-wide capture is not process attribution.",
                ],
            ),
            entry(
                sigma_archive,
                id="sigmahq-linux",
                engine="sigma",
                name="SigmaHQ Linux",
                version=version_of(args.sigma_commit[:12]),
                upstream_revision=args.sigma_commit,
                upstream_url="https://github.com/SigmaHQ/sigma",
                engine_requirement="pySigma 2.x SQLite backend",
                rules=kept,
                helpers=0,
                license="Detection Rule License (DRL) 1.1 for SigmaHQ rules. See LICENSE. Not MIT.",
                evidence=["process", "file"],
                limits=[
                    f"{excluded} files were excluded because the product or category is not a captured Linux event.",
                    "Category acceptance is not backend or evidence coverage. CommandLine is omitted unless the recorded arguments are complete.",
                    "This pack does not add HTTP, DNS or BPF community detections by itself.",
                    "Windows and Sysmon rules are not described as evaluated.",
                    "Missing fields stay missing, including under negation.",
                ],
            ),
        ],
    }
    (output / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n")
    (output / "README.md").write_text(
        """# Antinomie rules

Prepared community rule packs for Antinomie 0.6.2. This repository is not the
application source and contains no samples, captures or scan results.

The monitor downloads `catalog.json` from the public rules bucket
`https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve/catalog.json`
and the immutable archives that catalog names. It does not use the dataset
repository of the same name. Scans do not fetch rules and do not upload evidence.

## Engines

- YARA-X 1.21 scans a digest-verified sample, and captured core, guest-memory
  and recovered files when those targets are selected. Gaps are preserved.
- Suricata scans saved run-owned PCAP segments. It decodes and reassembles the
  capture. The displayed HTTP/DNS table is not the input.
- pySigma evaluates the retained normalized event journal for the captured
  Linux categories. Unsupported rules stay unevaluated.

A pack install does not install the engine. Missing Suricata or pySigma stays
an unavailable engine state.
"""
    )
    print(output / "catalog.json")


if __name__ == "__main__":
    main()
