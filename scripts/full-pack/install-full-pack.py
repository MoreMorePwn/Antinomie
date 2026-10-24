#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Install the tools of an Antinomie full pack into the app's data folder.

Run from the extracted pack (install-full-pack.sh wraps this). The files are
checked against SHA256SUMS, then each tool is copied to <data>/tools/<id> with
the same publish-by-rename the app uses, so the app sees it as installed.
Nothing is downloaded.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PACK = Path(__file__).resolve().parent
SYSTEM_PYTHON = "/usr/bin/python3"  # the interpreter the app builds the Sigma environment with


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(only_prefixes):
    bad = []
    count = 0
    for line in (PACK / "SHA256SUMS").read_text().splitlines():
        digest, _, rel = line.partition("  ")
        if only_prefixes is not None and not any(rel.startswith(p) for p in only_prefixes):
            continue
        path = PACK / rel
        count += 1
        if not path.is_file() or sha256_file(path) != digest:
            bad.append(rel)
    return count, bad


def installed_version(tools, tool):
    try:
        manifest = json.loads((tools / tool["id"] / "tool.json").read_text())
        entry_exists = (tools / tool["id"] / tool["entry"]).exists()
    except (OSError, ValueError):
        return None
    return manifest.get("version") if manifest.get("id") == tool["id"] and entry_exists else None


def publish(partial, destination):
    shutil.rmtree(destination, ignore_errors=True)
    os.rename(partial, destination)


def install_tree(tools, tool):
    partial = tools / f".{tool['id']}.partial"
    shutil.rmtree(partial, ignore_errors=True)
    shutil.copytree(PACK / "tools" / tool["id"], partial, symlinks=True)
    publish(partial, tools / tool["id"])


def install_wheels(tools, tool, python, minimum):
    partial = tools / f".{tool['id']}.partial"
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True)
    try:
        version = subprocess.run([python, "-I", "-c", "import sys; print(*sys.version_info[:2], sep='.')"],
                                 check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        if tuple(int(x) for x in version.split(".")) < minimum:
            raise SystemExit(f"{tool['name']} needs Python 3.11 or newer; {python} is {version}")
        if version not in (tool.get("sigma_pythons") or []):
            raise SystemExit(f"this pack carries {tool['name']} wheels for Python "
                             f"{', '.join(tool.get('sigma_pythons') or [])}; {python} is {version}")
        venv = partial / "venv"
        subprocess.run([python, "-m", "venv", str(venv)], check=True)
        wheels = PACK / "wheels" / tool["id"]
        py = venv / "bin/python"
        subprocess.run([str(py), "-I", "-m", "pip", "install", "--disable-pip-version-check",
                        "--no-input", "--no-cache-dir", "--no-index", "--find-links", str(wheels),
                        "--require-hashes", "--only-binary=:all:", "--no-deps",
                        "-r", str(wheels / "requirements.txt")], check=True)
        subprocess.run([str(py), "-I", "-c", tool["check"]], check=True)
        (partial / "tool.json").write_text(json.dumps({"id": tool["id"], "version": tool["version"]}, indent=2))
    except (subprocess.CalledProcessError, OSError, SystemExit):
        shutil.rmtree(partial, ignore_errors=True)
        raise
    publish(partial, tools / tool["id"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default=str(Path.home() / "antinomie"),
                    help="Antinomie's data folder (default: ~/antinomie)")
    ap.add_argument("--list", action="store_true", help="show the pack's contents and change nothing")
    ap.add_argument("--force", action="store_true", help="reinstall tools already installed at this version")
    ap.add_argument("--only", help="comma-separated tool ids")
    ap.add_argument("--no-verify", action="store_true", help="skip the SHA256SUMS check")
    ap.add_argument("--python", default=SYSTEM_PYTHON, help="Python for the Sigma environment")
    ap.add_argument("--min-python", default="3.11", help=argparse.SUPPRESS)  # tests only
    args = ap.parse_args(argv)

    manifest = json.loads((PACK / "MANIFEST.json").read_text())
    chosen = [t for t in manifest["tools"] if not args.only or t["id"] in args.only.split(",")]
    if args.only and len(chosen) != len(args.only.split(",")):
        sys.exit("install-full-pack: unknown tool id in --only")
    data = Path(args.data_dir).expanduser().resolve()
    tools = data / "tools"
    if args.list:
        print(f"{manifest['name']} (source {manifest.get('source_commit')})")
        for t in chosen:
            state = installed_version(tools, t) if tools.is_dir() else None
            print(f"  {t['id']:<12} {t['version']:<28} {t['kind']:<6} installed: {state or '-'}")
        for e in manifest["left_out"]:
            print(f"  left out: {e['id']} ({e['reason']})")
        return 0
    if data == Path("/") or not data.is_absolute():
        sys.exit("install-full-pack: refusing this data folder")

    if not args.no_verify:
        prefixes = None
        if args.only:
            prefixes = ["tools/" + t["id"] + "/" if t["kind"] == "tree" else "wheels/" + t["id"] + "/"
                        for t in chosen]
        print("checking SHA256SUMS ...", flush=True)
        count, bad = verify(prefixes)
        if bad:
            sys.exit("install-full-pack: these files fail their SHA-256 check; nothing was installed:\n  "
                     + "\n  ".join(bad[:20]))
        print(f"{count} files verified")
    tools.mkdir(parents=True, exist_ok=True)
    for t in chosen:
        current = installed_version(tools, t)
        if current == t["version"] and not args.force:
            print(f"  {t['id']}: {current} already installed")
            continue
        print(f"  {t['id']}: installing {t['version']}" + (f" over {current}" if current else ""), flush=True)
        if t["kind"] == "tree":
            install_tree(tools, t)
        else:
            install_wheels(tools, t, args.python, tuple(int(x) for x in args.min_python.split(".")))
    print(f"done: {tools}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
