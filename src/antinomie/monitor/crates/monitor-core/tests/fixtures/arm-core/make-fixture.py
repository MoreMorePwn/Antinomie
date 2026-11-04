#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build thumb-crash.core, the 32-bit ARM core fixture of the core reader tests.

    arm-linux-gnueabihf-gcc -static -O1 -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard -o crash crash.c
    (ulimit -c unlimited; qemu-arm-static ./crash)        # SIGSEGV in a Thumb function
    python3 make-fixture.py crash qemu_crash_*.core thumb-crash.core

The notes (NT_PRSTATUS in the compat layout, NT_PRPSINFO, NT_AUXV) are the real
ones qemu-user wrote for the crash: ELFCLASS32, EM_ARM, CORE owner, pc in Thumb
state (cpsr bit 5). qemu-user keeps no executable pages, so the program's own
first page (its code) stands for the text mapping, with the stack page at sp.
"""
import struct
import sys

binary, core, out = (open(sys.argv[1], 'rb').read(), open(sys.argv[2], 'rb').read(), sys.argv[3])
phoff = struct.unpack_from('<I', core, 28)[0]
count = struct.unpack_from('<H', core, 44)[0]
phdrs = [struct.unpack_from('<8I', core, phoff + 32 * i) for i in range(count)]
note = next(core[o:o + fs] for t, o, v, p, fs, ms, fl, al in phdrs if t == 4)
sp = None
c = 0
while c < len(note):
    namesz, descsz, kind = struct.unpack_from('<3I', note, c)
    desc_at = c + 12 + ((namesz + 3) & ~3)
    if kind == 1:
        sp = struct.unpack_from('<I', note, desc_at + 72 + 13 * 4)[0]
    c = desc_at + ((descsz + 3) & ~3)
page = sp & ~0xfff
stack = next(
    core[o + page - v:o + page - v + 0x1000]
    for t, o, v, p, fs, ms, fl, al in phdrs
    if t == 1 and fs and v <= page < v + fs
)
text = binary[:0x1000]  # a static ARM executable loads at 0x10000 from file offset 0
notes_at = 52 + 3 * 32
text_at = (notes_at + len(note) + 0xfff) & ~0xfff
stack_at = text_at + 0x1000
head = bytearray(52)
head[:16] = b'\x7fELF\x01\x01\x01\x00' + bytes(8)
struct.pack_into('<HHIIIIIHHHHHH', head, 16, 4, 40, 1, 0, 52, 0, 0x5000200, 52, 32, 3, 0, 0, 0)
ph = struct.pack('<8I', 4, notes_at, 0, 0, len(note), 0, 0, 0)
ph += struct.pack('<8I', 1, text_at, 0x10000, 0, 0x1000, 0x1000, 5, 0x1000)
ph += struct.pack('<8I', 1, stack_at, page, 0, 0x1000, 0x1000, 6, 0x1000)
body = bytes(head) + ph + note
body += bytes(text_at - len(body)) + text + stack
open(out, 'wb').write(body)
