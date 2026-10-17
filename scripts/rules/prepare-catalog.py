#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the Antinomie rules catalog (schema 2) from pinned upstream sources.

The catalog lists where each rule collection lives upstream, the revision it
was pinned at, the SHA-256 of every file the monitor keeps and how the monitor
filters the files locally. It contains no rules. The monitor downloads from the
publishers, verifies the hashes and filters on the user's machine, so nothing
here redistributes anyone's rules.

Every source is downloaded into its own new directory under --downloads, which
is treated as untrusted data: it is hashed and parsed, never executed.

Usage:
  python3 -I prepare-catalog.py OUTPUT_DIR --downloads DIR [--pin ID=REVISION ...]
                                [--count ID=RULES ...] [--report FILE]

Writes OUTPUT_DIR/catalog.json, README.md and NOTICE. Publishing them is a
separate step (publish-rules.py).
"""
import argparse
import collections
import datetime
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

BUCKET = "https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve"
API = "https://api.github.com"
APP = ">=0.6.2"
MAX_DOWNLOAD = 128 * 1024 * 1024
USER_AGENT = "antinomie-catalog-generator"

# A rule's own license meta is allowed when it starts with one of these.
ALLOWED_RULE_LICENSES = [
    "CC BY-SA 4.0",
    "CC BY 4.0",
    "Detection Rule License 1.1",
    "DRL-1.1",
    "BSD 2-Clause",
    "Apache License 2.0",
    "This Yara rule is provided under the Apache License 2.0",
    "MIT",
]
# Repository licenses that allow local use of the rules.
ALLOWED_REPOSITORY_LICENSES = [
    "DRL-1.1",
    "BSD-2-Clause",
    "Apache-2.0",
    "MIT",
    "GPL-3.0",
    "GPL-2.0",
    "Unlicense",
    "CC0-1.0",
    "CC-BY-4.0",
    "CC-BY-SA-4.0",
]
# Repositories whose license file the YARA-Forge package header does not
# recognise. Each is checked against the repository itself before it is used.
HEADER_MISSES = {"https://github.com/deadbits/yara-rules": "Unlicense"}

SIGMA_PREFIXES = [
    "rules/linux/process_creation/",
    "rules/linux/file_event/",
    "rules/linux/network_connection/",
    "rules/linux/auditd/",
    "rules-threat-hunting/linux/",
]
SIGMA_KEEP = [
    {"product": "linux", "category": "process_creation"},
    {"product": "linux", "category": "file_event"},
    {"product": "linux", "category": "network_connection"},
    {"product": "linux", "service": "auditd"},
]

RULE_START = re.compile(r"^(?:(?:private|global)\s+)*rule\s+(\w+)", re.M)
SET_MARKER = "/*\n * YARA Rule Set\n"


class Run:
    def __init__(self, args):
        self.args = args
        self.downloads = Path(args.downloads)
        self.warnings = []
        self.cache_file = Path(args.api_cache) if args.api_cache else None
        self.api_cache = {}
        if self.cache_file and self.cache_file.is_file():
            self.api_cache = json.loads(self.cache_file.read_text())
        self.pins = dict(item.split("=", 1) for item in args.pin)
        self.counts = dict(item.split("=", 1) for item in args.count)

    def warn(self, text):
        self.warnings.append(text)
        print("warning: " + text, file=sys.stderr)

    def directory(self, name):
        path = self.downloads / name
        path.mkdir(parents=True, exist_ok=False)
        return path

    def request(self, url, accept=None):
        if not url.startswith("https://"):
            raise SystemExit(f"refusing non-https URL {url}")
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        token = os.environ.get("GITHUB_TOKEN")
        if token and url.startswith(API):
            headers["Authorization"] = "Bearer " + token
        return urllib.request.Request(url, headers=headers)

    def api(self, path):
        url = API + path
        if url not in self.api_cache:
            try:
                with urllib.request.urlopen(self.request(url, "application/vnd.github+json"), timeout=60) as reply:
                    self.api_cache[url] = json.load(reply)
            except urllib.error.HTTPError as error:
                self.api_cache[url] = {"_error": error.code}
            if self.cache_file:
                self.cache_file.write_text(json.dumps(self.api_cache))
        return self.api_cache[url]

    def download(self, url, directory, name):
        """Download `url` to directory/name. Returns (path, size, sha256, headers)."""
        path = directory / name
        digest = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(self.request(url), timeout=300) as reply, path.open("wb") as out:
            headers = dict(reply.headers)
            while True:
                chunk = reply.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise SystemExit(f"{url} is larger than {MAX_DOWNLOAD} bytes")
                digest.update(chunk)
                out.write(chunk)
        return path, size, digest.hexdigest(), headers


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def count_yara(text):
    names = RULE_START.findall(text)
    helpers = len(re.findall(r"^private\s+rule\s", text, re.M))
    return len(names) - helpers, helpers


def count_sids(text):
    """Rules in a Suricata file: one sid per rule, rules may span lines."""
    live = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return len(re.findall(r"\bsid\s*:\s*\d+\s*;", live))


# --- YARA-Forge ------------------------------------------------------------

def classify_license(text):
    """Map a license text from a YARA-Forge set header to an SPDX identifier."""
    flat = " ".join(text.split())
    if not flat or "NO LICENSE SET" in flat:
        return "none"
    if "Detection Rule License" in flat:
        return "DRL-1.1"
    if "GNU GENERAL PUBLIC LICENSE" in flat.upper():
        if "Version 3" in flat:
            return "GPL-3.0"
        if "Version 2" in flat:
            return "GPL-2.0"
    if "Apache License" in flat and "Version 2.0" in flat:
        return "Apache-2.0"
    if re.search(r"\bMIT License\b", flat):
        return "MIT"
    if "Redistribution and use in source and binary forms" in flat:
        head = flat[:1700]
        return "BSD-3-Clause" if re.search(r"Neither the name|3\. ", head) else "BSD-2-Clause"
    return "unknown"


def repository_key(url):
    return url.strip().rstrip("/").removesuffix(".git").lower()


def split_sets(text):
    sets = []
    parts = text.split(SET_MARKER)
    for part in parts[1:]:
        header, _, body = part.partition("\n */")
        def field(key):
            match = re.search(r"^[ *]*" + re.escape(key) + r"\s*(.*)$", header, re.M)
            return match.group(1).strip() if match else ""
        license_text = header.partition("\n * LICENSE")[2]
        license_text = " ".join(line.strip(" *") for line in license_text.splitlines() if line.strip(" *"))
        sets.append({
            "name": field("Repository Name:"),
            "repository": field("Repository:"),
            "license_text": license_text,
            "body": body,
        })
    return sets


def yara_blocks(body):
    """Top-level rules; YARA-Forge closes every rule with a lone '}' in column 0."""
    current = None
    for line in body.splitlines(keepends=True):
        if current is None and RULE_START.match(line):
            current = [line]
            continue
        if current is not None:
            current.append(line)
            if line.rstrip("\n") == "}":
                yield "".join(current)
                current = None


def own_license(block):
    match = re.search(r'^\s*(?:malpedia_)?license\s*=\s*"([^"]*)"', block, re.M)
    if not match:
        return None
    value = match.group(1).strip()
    return None if value.lower() in ("", "n/a", "none", "unknown", "-") else value


def yara_slug(url):
    return "/".join(repository_key(url).rsplit("/", 2)[-2:])


def decide(block, repository, table, allowed_repo):
    """Mirror of the monitor's decision: returns (basis, reason)."""
    own = own_license(block)
    entry = table.get(repository_key(repository), {"license": "none"})["license"]
    repo_ok = entry in allowed_repo
    if own is not None:
        if own.startswith(tuple(ALLOWED_RULE_LICENSES)):
            return "own", None
        if repo_ok and yara_slug(repository) in own.lower():
            return "repository", None
        return None, "own license not allowed"
    if repo_ok:
        return "repository", None
    return None, "repository has no license"


def build_yara_forge(run):
    pack_id = "yara-forge-core"
    directory = run.directory(pack_id)
    release = run.api("/repos/YARAHQ/yara-forge/releases/latest")
    tag = run.pins.get(pack_id) or release.get("tag_name")
    if not tag:
        raise SystemExit("cannot resolve the latest YARA-Forge release")
    asset_name = "yara-forge-rules-core.zip"
    url = f"https://github.com/YARAHQ/yara-forge/releases/download/{tag}/{asset_name}"
    path, size, digest, _ = run.download(url, directory, asset_name)
    published = {a["name"]: a.get("digest", "") for a in release.get("assets", [])} if release.get("tag_name") == tag else {}
    if published.get(asset_name) and published[asset_name] != "sha256:" + digest:
        raise SystemExit(f"{asset_name} does not match the digest GitHub publishes for release {tag}")
    member = "packages/core/yara-rules-core.yar"
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(member)
        if info.file_size > 64 * 1024 * 1024:
            raise SystemExit("the YARA-Forge package is unexpectedly large")
        data = archive.read(member)
    text = data.decode("utf-8")
    sets = split_sets(text)
    # License table from the package headers, completed from the repositories.
    table = {}
    for item in sets:
        key = repository_key(item["repository"])
        license_id = classify_license(item["license_text"])
        if license_id == "unknown":
            run.warn(f"{item['repository']}: the header license is not recognised; treated as none")
            license_id = "none"
        table.setdefault(key, {"license": license_id, "url": "", "name": item["repository"].strip().rstrip("/")})
    remaining = run.api("/rate_limit").get("resources", {}).get("core", {}).get("remaining", 0)
    for key, entry in sorted(table.items()):
        slug = entry["name"].removeprefix("https://github.com/")
        if entry["license"] != "none":
            continue
        # Repositories the header calls unlicensed are checked once more.
        if remaining < 12:
            run.warn(f"{slug}: not re-checked against GitHub (rate limit)")
            continue
        info = run.api(f"/repos/{slug}/license")
        remaining -= 1
        spdx = (info.get("license") or {}).get("spdx_id")
        if spdx and spdx not in ("NOASSERTION", "null"):
            expected = HEADER_MISSES.get(entry["name"].lower())
            if expected != spdx:
                run.warn(f"{slug}: GitHub reports {spdx} but the package header says no license; treated as none")
            else:
                entry["license"] = spdx
                entry["url"] = info.get("html_url", entry["name"])
        elif entry["name"].lower() in HEADER_MISSES:
            run.warn(f"{slug}: expected {HEADER_MISSES[entry['name'].lower()]} was not confirmed")
    for entry in table.values():
        if not entry["url"]:
            entry["url"] = entry["name"]
    published = {entry["name"]: {"license": entry["license"], "url": entry["url"]} for entry in table.values()}
    totals = collections.Counter()
    per_repo = collections.OrderedDict()
    for item in sets:
        for block in yara_blocks(item["body"]):
            totals["rules"] += 1
            own = own_license(block)
            if own is not None and own.startswith(tuple(ALLOWED_RULE_LICENSES)):
                totals["v1_kept"] += 1
            basis, reason = decide(block, item["repository"], table, ALLOWED_REPOSITORY_LICENSES)
            if basis:
                totals["kept_" + basis] += 1
                if re.match(r"(?:global\s+)?private\s", block):
                    totals["kept_helpers"] += 1
            else:
                totals["dropped_" + reason.replace(" ", "_")] += 1
            per_repo.setdefault(item["name"] or item["repository"], collections.Counter())[basis or reason] += 1
    kept = totals["kept_own"] + totals["kept_repository"]
    unlicensed = totals["dropped_repository_has_no_license"]
    pack = {
        "id": pack_id,
        "engine": "yara",
        "name": "YARA-Forge Core",
        "homepage": "https://github.com/YARAHQ/yara-forge",
        "license": "Each rule's own license, or its source repository's license when the rule names none. Mixed; not one MIT license.",
        "license_url": "https://github.com/YARAHQ/yara-forge",
        "revision": tag,
        "revision_kind": "release",
        "app": APP,
        "engine_requirement": "YARA-X 1.21",
        "rules": int(run.counts.get(pack_id, kept - totals["kept_helpers"])),
        "helpers": totals["kept_helpers"],
        "evidence": ["sample", "memory", "recovered-file"],
        "limits": [
            "Rules whose own license is not allowed, and rules from repositories without a license file, are removed locally unless you opt in to the latter.",
            "Rules that YARA-X cannot compile are removed locally.",
        ],
        "sources": [{
            "url": url,
            "format": "zip",
            "size": size,
            "sha256": digest,
            "paths": ["packages/core/"],
            "files": [{"path": member, "sha256": sha256_bytes(data)}],
        }],
        "filter": {
            "kind": "yara-forge",
            "allowed_licenses": ALLOWED_RULE_LICENSES,
            "allowed_repository_licenses": ALLOWED_REPOSITORY_LICENSES,
            "repository_licenses": dict(sorted(published.items())),
        },
        "options": [{
            "id": "include-unlicensed",
            "label": f"Also include about {unlicensed} rules from repositories that have no license file",
            "default": False,
            "warning": "These repositories publish no license, so the rules are all rights reserved. Antinomie only reads them on this computer and never redistributes them; use them at your own responsibility.",
        }],
        "notices": [],
    }
    summary = {
        "package_rules": totals["rules"],
        "kept_by_own_license_only (previous filter)": totals["v1_kept"],
        "kept_with_repository_fallback": kept,
        "  of which own license": totals["kept_own"],
        "  of which repository license": totals["kept_repository"],
        "dropped: own license not allowed": totals["dropped_own_license_not_allowed"],
        "dropped: repository without a license (opt-in)": unlicensed,
        "repositories": len(table),
        "repositories_without_license": sum(1 for e in table.values() if e["license"] == "none"),
    }
    return pack, summary


# --- Elastic ---------------------------------------------------------------

def codeload(run, pack_id, repo, ref, directory):
    url = f"https://codeload.github.com/{repo}/tar.gz/{ref}"
    return url, *run.download(url, directory, f"{ref[:12]}.tar.gz")


def tar_files(path, strip, wanted):
    """Regular files of a tar.gz whose stripped path satisfies `wanted`: {path: bytes}."""
    found = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            parts = member.name.split("/")[strip:]
            name = "/".join(parts)
            if parts and wanted(name):
                found[name] = archive.extractfile(member).read()
    return found


def build_elastic(run):
    pack_id = "elastic-protections-yara"
    directory = run.directory(pack_id)
    commit = run.pins.get(pack_id)
    if not commit:
        repo = run.api("/repos/elastic/protections-artifacts")
        commit = run.api(f"/repos/elastic/protections-artifacts/commits/{repo.get('default_branch', 'main')}")["sha"]
    url, path, size, digest, _ = codeload(run, pack_id, "elastic/protections-artifacts", commit, directory)
    files = tar_files(path, 1, lambda n: (n.startswith("yara/rules/") and n.endswith(".yar")) or n == "LICENSE.txt")
    if "LICENSE.txt" not in files or "Elastic License" not in files["LICENSE.txt"].decode("utf-8", "replace"):
        raise SystemExit("the Elastic repository no longer carries the Elastic License as LICENSE.txt")
    rules = [n for n in files if n.endswith(".yar")]
    linux = sum(count_yara(files[n].decode("utf-8", "replace"))[0] for n in rules if n.startswith("yara/rules/Linux_"))
    total = sum(count_yara(files[n].decode("utf-8", "replace"))[0] for n in rules)
    return {
        "id": pack_id,
        "engine": "yara",
        "name": "Elastic protections-artifacts YARA",
        "homepage": "https://github.com/elastic/protections-artifacts",
        "license": "Elastic License 2.0. Free for your own use; you may not provide the rules to others as a hosted or managed service or remove license-key protections. Not an open-source license.",
        "license_url": f"https://github.com/elastic/protections-artifacts/blob/{commit}/LICENSE.txt",
        "revision": commit,
        "revision_kind": "commit",
        "app": APP,
        "engine_requirement": "YARA-X 1.21",
        "rules": int(run.counts.get(pack_id, total)),
        "helpers": 0,
        "evidence": ["sample", "memory", "recovered-file"],
        "limits": [
            f"Includes all {total} rules; {linux} are Linux rules and the rest target Windows, macOS and multi-platform malware that a recorded sample or memory can still contain.",
            "Rules that YARA-X cannot compile are reported when the pack is installed.",
        ],
        "sources": [{
            "url": url,
            "format": "tar.gz",
            "size": size,
            "strip": 1,
            "paths": ["yara/rules/"],
            "files": [{"path": n, "sha256": sha256_bytes(files[n])} for n in sorted(files)],
        }],
        "filter": {"kind": "copy", "extensions": [".yar"], "support": ["LICENSE.txt"]},
        "options": [],
        "notices": [
            "These rules are licensed under the Elastic License 2.0, which is not an open-source license. Antinomie downloads them from Elastic and uses them only on this computer.",
        ],
    }, {"rules": total, "linux_rules": linux, "files": len(rules)}


# --- Suricata and abuse.ch ---------------------------------------------------

def build_suricata(run):
    pack_id = "suricata-builtin"
    directory = run.directory(pack_id)
    tag = run.pins.get(pack_id)
    if not tag:
        releases = run.api("/repos/OISF/suricata/releases?per_page=30")
        tag = next(r["tag_name"] for r in releases if r["tag_name"].startswith("suricata-7.0."))
    ref = run.api(f"/repos/OISF/suricata/git/ref/tags/{tag}")["object"]
    commit = ref["sha"]
    if ref["type"] == "tag":
        commit = run.api(f"/repos/OISF/suricata/git/tags/{commit}")["object"]["sha"]
    listing = run.api(f"/repos/OISF/suricata/contents/rules?ref={commit}")
    names = sorted(item["name"] for item in listing if item["name"].endswith(".rules"))
    sources = []
    total = 0
    for name in names + ["COPYING"]:
        folder = "rules/" if name != "COPYING" else ""
        url = f"https://raw.githubusercontent.com/OISF/suricata/{commit}/{folder}{name}"
        path, size, digest, _ = run.download(url, directory, name)
        if name.endswith(".rules"):
            total += count_sids(path.read_text(errors="replace"))
        sources.append({
            "url": url,
            "format": "file",
            "size": size,
            "sha256": digest,
            "files": [{"path": name, "sha256": digest}],
        })
    return {
        "id": pack_id,
        "engine": "ids",
        "name": "Suricata built-in rules",
        "homepage": "https://github.com/OISF/suricata",
        "license": "GPL-2.0",
        "license_url": f"https://github.com/OISF/suricata/blob/{commit}/COPYING",
        "revision": tag,
        "revision_kind": "release",
        "app": APP,
        "engine_requirement": "Suricata 7",
        "rules": int(run.counts.get(pack_id, total)),
        "helpers": 0,
        "evidence": ["pcap"],
        "limits": [
            "Decoder, stream and application-layer event rules. They report malformed or unusual traffic, not malware families.",
            "Rules that need an external dataset or a TLS fingerprint keyword are reported and not loaded.",
        ],
        "sources": sources,
        "filter": {"kind": "copy", "extensions": [".rules"], "support": ["COPYING"]},
        "options": [],
        "notices": [],
    }, {"rules": total, "files": len(names)}


def build_et_open(run):
    pack_id = "emerging-threats-open"
    directory = run.directory(pack_id)
    url = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
    path, size, digest, headers = run.download(url, directory, "emerging.rules.tar.gz")
    keep_support = {"rules/LICENSE", "rules/BSD-License.txt", "rules/gpl-2.0.txt", "rules/classification.config"}
    files = tar_files(path, 0, lambda n: n in keep_support or (n.startswith("rules/") and n.endswith(".rules")))
    total = sum(count_sids(files[n].decode("utf-8", "replace")) for n in files if n.endswith(".rules"))
    stamp = headers.get("Last-Modified") or ""
    try:
        day = datetime.datetime.strptime(stamp, "%a, %d %b %Y %H:%M:%S %Z").strftime("%Y-%m-%d")
    except ValueError:
        day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    return {
        "id": pack_id,
        "engine": "ids",
        "name": "Emerging Threats Open",
        "homepage": "https://rules.emergingthreats.net/",
        "license": "Mixed: BSD for the Emerging Threats rules and GPLv2 for some SID ranges. See the LICENSE files installed with the pack. Not MIT.",
        "license_url": "https://rules.emergingthreats.net/open/suricata-7.0.3/",
        "revision": f"snapshot-{day}",
        "revision_kind": "rolling",
        "app": APP,
        "engine_requirement": "Suricata 7",
        "rules": int(run.counts.get(pack_id, total)),
        "helpers": 0,
        "evidence": ["pcap"],
        "limits": [
            "Emerging Threats updates this download in place. The hashes in this catalog describe the snapshot it was written from; a newer download installs and is recorded as different.",
            "Rules that require an external dataset or a TLS fingerprint keyword are reported and not loaded.",
            "Duplicate SIDs keep the first copy.",
            "VM-wide capture is not process attribution.",
        ],
        "sources": [{
            "url": url,
            "format": "tar.gz",
            "size": size,
            "sha256": digest,
            "rolling": True,
            "paths": ["rules/"],
            "files": [{"path": n, "sha256": sha256_bytes(files[n])} for n in sorted(files)],
        }],
        "filter": {
            "kind": "copy",
            "extensions": [".rules"],
            "support": ["LICENSE", "BSD-License.txt", "gpl-2.0.txt", "classification.config"],
        },
        "options": [],
        "notices": [],
    }, {"rules": total, "files": sum(1 for n in files if n.endswith('.rules'))}


def build_sslbl(run):
    pack_id = "abuse-ch-sslbl"
    directory = run.directory(pack_id)
    url = "https://sslbl.abuse.ch/blacklist/sslblacklist.rules"
    path, size, digest, _ = run.download(url, directory, "sslblacklist.rules")
    text = path.read_text(errors="replace")
    total = count_sids(text)
    match = re.search(r"Last updated: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) UTC", text)
    stamp = "".join(match.groups()[:3]) + "T" + "".join(match.groups()[3:]) + "Z" if match else "snapshot"
    return {
        "id": pack_id,
        "engine": "ids",
        "name": "abuse.ch SSL certificate blacklist",
        "homepage": "https://sslbl.abuse.ch/",
        "license": "CC0 1.0: abuse.ch states the SSLBL datasets may be used for commercial and non-commercial purposes without limitation.",
        "license_url": "https://sslbl.abuse.ch/blacklist/",
        "revision": stamp,
        "revision_kind": "rolling",
        "app": APP,
        "engine_requirement": "Suricata 7",
        "rules": int(run.counts.get(pack_id, total)),
        "helpers": 0,
        "evidence": ["pcap"],
        "limits": [
            "Matches the SHA-1 fingerprint of a TLS certificate seen in the capture. abuse.ch rewrites this list continuously, so the hash in this catalog describes one snapshot.",
            "Rules that use a JA3 or other TLS fingerprint keyword are reported and not loaded.",
        ],
        "sources": [{
            "url": url,
            "format": "file",
            "size": size,
            "sha256": digest,
            "rolling": True,
            "files": [{"path": "sslblacklist.rules", "sha256": digest}],
        }],
        "filter": {"kind": "copy", "extensions": [".rules"], "support": []},
        "options": [],
        "notices": [],
    }, {"rules": total}


# --- SigmaHQ ---------------------------------------------------------------

def logsource(doc):
    fields = {}
    inside = False
    for line in doc.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        width = len(line) - len(line.lstrip())
        if not inside:
            inside = width == 0 and line.rstrip() == "logsource:"
            continue
        if width == 0:
            break
        key, _, value = line.strip().partition(":")
        fields[key] = value.strip().strip("'\"").lower()
    return fields.get("product", ""), fields.get("category", ""), fields.get("service", "")


def build_sigma(run):
    pack_id = "sigmahq-linux"
    directory = run.directory(pack_id)
    commit = run.pins.get(pack_id) or run.api("/repos/SigmaHQ/sigma/commits/master")["sha"]
    url, path, size, digest, _ = codeload(run, pack_id, "SigmaHQ/sigma", commit, directory)
    files = tar_files(
        path, 1,
        lambda n: n == "LICENSE" or (n.endswith(".yml") and n.startswith(tuple(SIGMA_PREFIXES))),
    )
    if "Detection Rule License" not in files.get("LICENSE", b"").decode("utf-8", "replace"):
        raise SystemExit("the SigmaHQ LICENSE no longer names the Detection Rule License")
    per = collections.Counter()
    kept = 0
    for name, data in files.items():
        if not name.endswith(".yml"):
            continue
        for doc in data.decode("utf-8", "replace").replace("\r\n", "\n").split("\n---\n"):
            if "title:" not in doc:
                continue
            product, category, service = logsource(doc)
            if any(
                (not k.get("product") or k["product"] == product)
                and (not k.get("category") or k["category"] == category)
                and (not k.get("service") or k["service"] == service)
                for k in SIGMA_KEEP
            ):
                kept += 1
                per[category or f"service:{service}"] += 1
    return {
        "id": pack_id,
        "engine": "sigma",
        "name": "SigmaHQ Linux",
        "homepage": "https://github.com/SigmaHQ/sigma",
        "license": "Detection Rule License (DRL) 1.1 for SigmaHQ rules. Not MIT.",
        "license_url": f"https://github.com/SigmaHQ/sigma/blob/{commit}/LICENSE",
        "revision": commit,
        "revision_kind": "commit",
        "app": APP,
        "engine_requirement": "pySigma 2.x SQLite backend",
        "rules": int(run.counts.get(pack_id, kept)),
        "helpers": 0,
        "evidence": ["process", "file"],
        "limits": [
            "Rules are imported by log source: " + ", ".join(f"{count} {key}" for key, count in sorted(per.items())) + ".",
            "Antinomie evaluates process_creation, file_event and network_connection rules whose fields it records (a connection is a connect() it saw succeed, with its destination address and port). auditd rules need auditd log records, which a recording does not hold, and rules that use fields it does not record (for example ParentImage or DestinationHostname) are imported and listed as not evaluated, each with its reason.",
            "CommandLine is omitted unless the recorded arguments are complete.",
            "Windows and Sysmon rules are not part of this pack.",
            "Missing fields stay missing, including under negation.",
        ],
        "sources": [{
            "url": url,
            "format": "tar.gz",
            "size": size,
            "strip": 1,
            "paths": SIGMA_PREFIXES,
            "files": [{"path": n, "sha256": sha256_bytes(files[n])} for n in sorted(files)],
        }],
        "filter": {"kind": "sigma", "keep": SIGMA_KEEP},
        "options": [],
        "notices": [],
    }, {"rules": kept, "by_category": dict(sorted(per.items())), "files": len(files) - 1}


# --- Output ------------------------------------------------------------------

README = """# Antinomie rules

This is the rules catalog for Antinomie {app}. It lists where each community
rule collection lives upstream, the exact revision it was pinned at, the
SHA-256 of every file Antinomie keeps and how Antinomie filters the files on
the user's computer. It contains **no rules**, and no samples, captures or scan
results.

`catalog.json` (schema 2) is what Tools > Rule manager reads:
`{bucket}/catalog.json`. Nothing is
downloaded until the person allows downloads and presses a button; scans never
download rules or upload evidence.

## How a pack is installed

1. The monitor downloads the files from the publisher's own HTTPS URL
   (GitHub, rules.emergingthreats.net, sslbl.abuse.ch). Redirects may only
   reach that publisher's hosts.
2. Every kept file is checked against the SHA-256 in the catalog. A pinned
   source that differs is refused and nothing is installed. Sources the
   publisher updates in place (marked `rolling`) install and are recorded as
   different from the catalog.
3. The monitor filters locally: licenses for YARA-Forge, log sources for
   Sigma, compile checks for YARA, keyword checks for Suricata.
4. The result is installed as a pack under the person's data directory with its
   source, revision, hashes and license, which the Rule manager, the rule-set
   list and each scan record show.

## Sources in this catalog

{table}

Licenses belong to the publishers. {notes}

The catalog itself (this file's JSON data) is MIT licensed, by MikiMiku
(MoreMorePwn). It was generated by `scripts/rules/prepare-catalog.py` in the
Antinomie repository from the revisions above, on {date}.
"""


def render_readme(catalog, bucket):
    rows = ["| Pack | Engine | Source | Revision | License |", "|---|---|---|---|---|"]
    for pack in catalog["packs"]:
        license_line = pack["license"].split(". ")[0].rstrip(".")
        rows.append(
            f"| {pack['name']} | {pack['engine']} | {pack['homepage']} | {pack['revision_kind']} {pack['revision']} | {license_line} |"
        )
    notes = (
        "The Elastic rules are under the Elastic License 2.0, which is not an "
        "open-source license; YARA-Forge repositories without a license file are "
        "all rights reserved and are used only if a person opts in."
    )
    return README.format(
        app=APP.lstrip(">="),
        bucket=bucket.rstrip("/"),
        table="\n".join(rows),
        notes=notes,
        date=catalog["generated"],
    )


def render_notice(catalog):
    lines = [
        "Antinomie rules catalog",
        "",
        "catalog.json and README.md are MIT licensed data by MikiMiku (MoreMorePwn).",
        "They describe where rule collections are published and how to verify them.",
        "No rule text from any collection is stored or redistributed here.",
        "",
        "Collections the catalog points to, each under its publisher's terms:",
        "",
    ]
    for pack in catalog["packs"]:
        lines += [f"- {pack['name']}: {pack['homepage']}", f"  License: {pack['license']}"]
        if pack.get("license_url"):
            lines.append(f"  License text: {pack['license_url']}")
        sources = pack["sources"]
        lines.append(f"  Fetched from: {sources[0]['url']}")
        if len(sources) > 1:
            lines.append(f"  and {len(sources) - 1} more files at the same revision (see catalog.json)")
    table = next((p["filter"]["repository_licenses"] for p in catalog["packs"] if p["filter"]["kind"] == "yara-forge"), {})
    if table:
        lines += ["", "YARA-Forge source repositories and the license this catalog records for each:", ""]
        for url, entry in table.items():
            lines.append(f"- {url}: {entry['license']}")
    lines.append("")
    return "\n".join(lines)


def compact_files(text):
    return re.sub(
        r'\{\s+"path": ("[^"]*"),\s+"sha256": ("[0-9a-f]{64}")\s+\}',
        r'{"path": \1, "sha256": \2}',
        text,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("output")
    parser.add_argument("--downloads", required=True, help="empty or new directory; one new subdirectory per pack")
    parser.add_argument("--pin", action="append", default=[], metavar="ID=REVISION", help="yara-forge-core=<tag>, elastic-protections-yara=<sha>, suricata-builtin=<tag>, sigmahq-linux=<sha>")
    parser.add_argument("--count", action="append", default=[], metavar="ID=RULES", help="replace an approximate rule count, for example with the monitor's compile-checked count")
    parser.add_argument("--bucket", default=BUCKET)
    parser.add_argument("--api-cache", default="", help="JSON file that keeps GitHub API answers between runs (unauthenticated requests are rate limited)")
    parser.add_argument("--report", default="", help="also write the generation report to this file")
    args = parser.parse_args()
    run = Run(args)
    run.downloads.mkdir(parents=True, exist_ok=True)
    builders = [build_yara_forge, build_elastic, build_suricata, build_et_open, build_sslbl, build_sigma]
    packs, summaries = [], {}
    for builder in builders:
        pack, summary = builder(run)
        packs.append(pack)
        summaries[pack["id"]] = summary
        print(f"{pack['id']}: {pack['revision_kind']} {pack['revision']}, about {pack['rules']} rules", file=sys.stderr)
    catalog = {
        "schema": 2,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
        "generator": "scripts/rules/prepare-catalog.py",
        "packs": packs,
    }
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "catalog.json").write_text(compact_files(json.dumps(catalog, indent=2)) + "\n")
    (output / "README.md").write_text(render_readme(catalog, args.bucket))
    (output / "NOTICE").write_text(render_notice(catalog))
    report = json.dumps({"summaries": summaries, "warnings": run.warnings}, indent=2)
    if args.report:
        Path(args.report).write_text(report + "\n")
    print(report)
    print(output / "catalog.json")


if __name__ == "__main__":
    main()
