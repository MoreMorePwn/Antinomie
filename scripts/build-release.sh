#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# build-release.sh — build the release executable and the release archive
# antinomie-<version>-linux-x86_64.tar.gz plus SHA256SUMS.
#
#   usage: scripts/build-release.sh OUTPUT_DIR
#
# The executable names its sources by remapped paths (/antinomie, /cargo, /target),
# never by this machine's home directory; the build fails if one remains.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: scripts/build-release.sh OUTPUT_DIR}"
MONITOR="$REPO/src/antinomie/monitor"
CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
TARGET_DIR="${CARGO_TARGET_DIR:-$MONITOR/target}"
# Resolve relative Cargo targets exactly as the build working directory does.
if [[ "$TARGET_DIR" != /* ]]; then
    TARGET_DIR="$MONITOR/$TARGET_DIR"
fi

# The last matching remapping wins: the home directory first, then the
# more specific locations below it.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/home/builder \
--remap-path-prefix=$RUSTUP_DIR=/rustup --remap-path-prefix=$CARGO_DIR=/cargo \
--remap-path-prefix=$REPO=/antinomie --remap-path-prefix=$TARGET_DIR=/target"
# Standard modules ship generated sources; rebuilding must not mutate the cache.
export YRX_REGENERATE_MODULES_RS="${YRX_REGENERATE_MODULES_RS:-false}"
(cd "$MONITOR" && cargo build --release --locked)

version="$("$TARGET_DIR/release/antinomie-monitor" --version | awk '{print $2}')"
name="antinomie-$version"
stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT
package="$stage/$name"
mkdir -p "$package"
cp "$TARGET_DIR/release/antinomie-monitor" "$package/"
strip "$package/antinomie-monitor"
# Read the entire stream: grep -q can hide a match behind strings' SIGPIPE
# when pipefail is enabled.
for private_path in "$HOME" "$REPO" "$TARGET_DIR"; do
    if strings "$package/antinomie-monitor" | grep -F "$private_path" >/dev/null; then
        echo "build-release: the executable still names $private_path; refusing to package" >&2
        exit 1
    fi
done
cp "$REPO/install.sh" "$REPO/CHANGELOG.md" "$REPO/LICENSE" "$REPO/LICENSING.md" \
   "$REPO/THIRD-PARTY-NOTICES.md" "$package/"
cp "$MONITOR/assets/antinomie.desktop" "$MONITOR/assets/antinomie.svg" "$package/"
cp -r "$REPO/LICENSES" "$package/"
python3 "$REPO/scripts/check-licenses.py" --output "$package/LICENSES/cargo-dependencies"
# Preserve notices from the toolchain/libc actually used by this build.
rust_notice="$(rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html"
test -f "$rust_notice"
cp "$rust_notice" "$package/LICENSES/third-party/Rust-Standard-Library-COPYRIGHT.html"
if [[ -f /usr/share/doc/musl/copyright ]]; then
    cp /usr/share/doc/musl/copyright "$package/LICENSES/third-party/libc/musl-copyright.txt"
fi
python3 - "$REPO" "$package" "$version" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
repo, package = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def output(command):
    result = subprocess.run(command, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None
compiler = os.environ.get('ANTINOMIE_GUEST_CC', 'musl-gcc')
info = {
    'version': sys.argv[3],
    'source_commit': output(['git', 'rev-parse', 'HEAD']),
    'source_dirty': bool(output(['git', 'status', '--porcelain'])),
    'rustc': output(['rustc', '--version']),
    'guest_compiler': pathlib.Path(compiler).name,
    'guest_compiler_version': output([compiler, '--version']),
    'musl_package_version': output(['dpkg-query', '-W', '-f=${Version}', 'musl']),
    'notice_sha256': {
        name: hashlib.sha256((package / name).read_bytes()).hexdigest()
        for name in ['LICENSES/third-party/Rust-Standard-Library-COPYRIGHT.html',
                     'LICENSES/third-party/libc/musl-copyright.txt']
    },
}
(package / 'BUILD-INFO.json').write_text(json.dumps(info, indent=2) + '\n')
PY
cat > "$package/README.txt" <<TEXT
Antinomie $version (Linux x86-64)

Install for the current user (no root needed):
    ./install.sh            # antinomie command, application menu entry, icon
    ./install.sh --uninstall

Or run it in place:
    ./antinomie-monitor

Requirements: glibc 2.39 or newer (Debian 13, Ubuntu 24.04 or later), QEMU
(qemu-system-x86_64, qemu-img, GTK display backend) and access to /dev/kvm
for hardware acceleration (or select TCG). On Debian/Ubuntu install
qemu-system-x86 qemu-utils qemu-system-gui. Tools > App dependencies checks
runtime requirements at startup; install missing packages and Check again.
Missing requirements block their affected actions; saved recordings stay available.
Bases: Add base >
Download base (prebuilt, from the MoreMorePwn/antinomie-bases bucket) or
Build base. Creating a Debian VM also needs virt-customize (libguestfs-tools).

Static analysis runs in a bubblewrap sandbox (bwrap). Disassembly, rules
(YARA-X) and identification are built in. Decompilation (Ghidra),
capabilities (capa) and Detect It Easy use the system's copy when installed;
otherwise Tools > Analysis tools downloads them for Antinomie.

The Disks tab flattens a stopped VM's disk with qemu-img (qemu-utils) and
reads it in a bubblewrap sandbox bounded by prlimit (bubblewrap, util-linux);
the ext4 reader is built into antinomie-monitor.

Packet display filters and HTTP/DNS triage use installed TShark, with
Bubblewrap and Prlimit isolation/resource limits. On Debian/Ubuntu install
tshark bubblewrap util-linux. These tools are not bundled in this archive.

Licensing: original application code is GPL-3.0-only from 0.7.0. Earlier
releases remain MIT. Shared kernel headers, dependencies, separately installed
rule packs and the embedded guest build kit retain their own licenses.
See LICENSING.md, THIRD-PARTY-NOTICES.md and LICENSES/. Redistributors must
provide corresponding source to binary recipients; retain the source revision
and build instructions alongside the downloads.
BUILD-INFO.json records the source revision, compiler, musl package and notices.
TEXT
mkdir -p "$OUT"
archive="$OUT/$name-linux-x86_64.tar.gz"
# Reproducible: fixed member times (the commit time unless SOURCE_DATE_EPOCH is
# set), sorted names, numeric owners, and no name or time in the gzip header.
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct)}"
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${epoch}" -cf - "$name" | gzip -n >"$archive"
(cd "$OUT" && sha256sum "$(basename "$archive")" > SHA256SUMS)
cat "$OUT/SHA256SUMS"
