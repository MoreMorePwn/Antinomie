#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Rebuilds the two x86 ELF fixtures (needs gcc with -m32 linking).
set -e
cd "$(dirname "$0")"
gcc -nostdlib -static -Wl,-z,noseparate-code,--build-id=none -o x86_64.elf x86_64.S
gcc -m32 -nostdlib -static -Wl,-z,noseparate-code,--build-id=none -o i386.elf i386.S
