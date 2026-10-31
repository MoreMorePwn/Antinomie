#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Rebuild the benign listing fixtures with the Ubuntu cross compilers:
#   apt install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf gcc-i686-linux-gnu \
#       gcc-riscv64-linux-gnu binutils-mips-linux-gnu clang lld
set -eu
cd "$(dirname "$0")"
flags="-O1 -ffreestanding -nostdlib -static -fno-pic -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,-e,_start"
gcc $flags -no-pie -o x86_64.elf listing-fixture.c
i686-linux-gnu-gcc $flags -no-pie -o i386.elf listing-fixture.c
arm-linux-gnueabihf-gcc $flags -marm -o arm.elf listing-fixture.c
aarch64-linux-gnu-gcc $flags -o aarch64.elf listing-fixture.c
riscv64-linux-gnu-gcc $flags -o riscv64.elf listing-fixture.c
clang --target=mips-linux-gnu -O1 -ffreestanding -fno-pic -mno-abicalls -fno-stack-protector \
    -fno-asynchronous-unwind-tables -c -o mips.o listing-fixture.c
mips-linux-gnu-ld -e _start -o mips.elf mips.o
rm -f mips.o
strip --strip-debug ./*.elf 2>/dev/null || true
