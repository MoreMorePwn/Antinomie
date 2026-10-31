#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Build the base disk images the disk_image target patches: a small ext4
# filesystem of benign text files, raw and as qcow2. Usage: make-bases.sh [DIR]
set -euo pipefail
dir="${1:-${ANTINOMIE_FUZZ_DISKS:-/dev/shm/antinomie-fuzz-bases}}"
mkdir -p "$dir"
tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT
mkdir -p "$tree"/{etc,bin,tmp,home/user,var/log,a/b}
printf 'root:x:0:0:root:/root:/bin/sh\n' >"$tree/etc/passwd"
printf 'remember the milk\n' >"$tree/home/user/notes.txt"
printf 'boot ok\n' >"$tree/var/log/messages.log"
printf 'deep' >"$tree/a/b/deep.txt"
head -c 9000 /dev/zero | tr '\0' 'Z' >"$tree/bin/busybox"
ln -s /etc/shadow "$tree/etc/shadow-link"
ln -s /etc "$tree/etc/loop"
truncate -s 2M "$dir/ext4.raw"
mkfs.ext4 -q -F -b 1024 -O ^has_journal -L fuzz -d "$tree" "$dir/ext4.raw"
qemu-img convert -f raw -O qcow2 "$dir/ext4.raw" "$dir/ext4.qcow2"
qemu-img convert -c -f raw -O qcow2 "$dir/ext4.raw" "$dir/ext4.compressed.qcow2"
ls -l "$dir"
