#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Rebuilds the two ELF fixtures (needs aarch64-linux-gnu-gcc and arm-linux-gnueabihf-gcc).
set -e
cd "$(dirname "$0")"
aarch64-linux-gnu-gcc -nostdlib -static -Wl,-z,noseparate-code,--build-id=none -o aarch64.elf aarch64.S
arm-linux-gnueabihf-gcc -nostdlib -static -Wl,-z,noseparate-code,--build-id=none -o arm32.elf arm32.S
arm-linux-gnueabihf-gcc -nostdlib -static -Wl,-z,noseparate-code,--build-id=none -o arm32-stripped.elf arm32.S -s
