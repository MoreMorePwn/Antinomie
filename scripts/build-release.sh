#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-release.sh — build the release executable and the release archive
# antinomie-<version>-linux-x86_64.tar.gz plus SHA256SUMS.
#
#   usage: scripts/build-release.sh OUTPUT_DIR
#
# The executable names its sources by remapped paths (/antinomie, /cargo),
# never by this machine's home directory; the build fails if one remains.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: scripts/build-release.sh OUTPUT_DIR}"
MONITOR="$REPO/src/antinomie/monitor"
CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_DIR="${RUSTUP_HOME:-$HOME/.rustup}"

# The last matching remapping wins: the home directory first, then the
# more specific locations below it.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/home/builder \
--remap-path-prefix=$RUSTUP_DIR=/rustup --remap-path-prefix=$CARGO_DIR=/cargo \
--remap-path-prefix=$REPO=/antinomie"
(cd "$MONITOR" && cargo build --release --locked)

version="$("$MONITOR/target/release/antinomie-monitor" --version | awk '{print $2}')"
name="antinomie-$version"
stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT
package="$stage/$name"
mkdir -p "$package"
cp "$MONITOR/target/release/antinomie-monitor" "$package/"
strip "$package/antinomie-monitor"
if strings "$package/antinomie-monitor" | grep -qF "$HOME"; then
    echo "build-release: the executable still names $HOME; refusing to package" >&2
    exit 1
fi
cp "$REPO/install.sh" "$REPO/CHANGELOG.md" "$REPO/LICENSE" "$REPO/LICENSING.md" \
   "$REPO/THIRD-PARTY-NOTICES.md" "$package/"
cp "$MONITOR/assets/antinomie.desktop" "$MONITOR/assets/antinomie.svg" "$package/"
cp -r "$REPO/LICENSES" "$package/"
cat > "$package/README.txt" <<TEXT
Antinomie $version (Linux x86-64)

Install for the current user (no root needed):
    ./install.sh            # antinomie command, application menu entry, icon
    ./install.sh --uninstall

Or run it in place:
    ./antinomie-monitor

Requirements: glibc 2.39 or newer (Debian 13, Ubuntu 24.04 or later), QEMU
(qemu-system-x86_64, qemu-img) and access to /dev/kvm. Bases: Add base >
Download base (prebuilt, from the MoreMorePwn/antinomie-bases bucket) or
Build base. Creating a Debian VM also needs virt-customize (libguestfs-tools).

Static analysis runs in a bubblewrap sandbox (bwrap). Disassembly, rules
(YARA-X) and identification are built in. Decompilation (Ghidra),
capabilities (capa) and Detect It Easy use the system's copy when installed;
otherwise Tools > Analysis tools downloads them for Antinomie.

Licensing: see LICENSING.md; the executable is a composite of MIT
application code, its dependencies, the embedded analysis rule sets (their
own licenses, see THIRD-PARTY-NOTICES.md) and the embedded base build kit.
TEXT
mkdir -p "$OUT"
archive="$OUT/$name-linux-x86_64.tar.gz"
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner -czf "$archive" "$name"
(cd "$OUT" && sha256sum "$(basename "$archive")" > SHA256SUMS)
cat "$OUT/SHA256SUMS"
