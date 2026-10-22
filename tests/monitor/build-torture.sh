#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# build-torture.sh — build the Antinomie stress samples.
#
#   usage: tests/monitor/build-torture.sh OUTPUT_DIR [--static]
#
# Writes OUTPUT_DIR/ant-torture (every module), one ant-<module> per module,
# and the ant-static-* variants for static analysis. The default build links
# glibc dynamically and stops if a binary would need a newer glibc than the
# Debian trixie guest has (2.41); --static links the samples statically (the
# BusyBox guests need this).
#
# What each sample does with its options is documented in idk-docs:
# "Stress Samples - Arguments and Walkthrough.md".
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_dir="$here/torture"
output=${1:?usage: build-torture.sh OUTPUT_DIR [--static]}
mode=${2:-}
mkdir -p "$output"
output=$(cd "$output" && pwd)

link=()
if [[ $mode == --static ]]; then
    link=(-static)
elif [[ -n $mode ]]; then
    echo "unknown option $mode" >&2
    exit 2
fi

cflags=(-O2 -g -Wall -Wextra -Wno-unused-result -pthread -D_GNU_SOURCE -I"$source_dir")
sources=("$source_dir"/main.c "$source_dir"/load.c "$source_dir"/process.c "$source_dir"/files.c
    "$source_dir"/network.c "$source_dir"/kernel.c "$source_dir"/memory.c "$source_dir"/detect.c
    "$source_dir"/indicators.c)
modules=(syscall-flood long-run object-capture terminal-flood process-tree unkillable file-churn
    network-storm async-io decoder-zoo crash-core memory-tricks detect-yara detect-sigma detect-ids
    argv-env timing)

check_glibc() {
    [[ $mode == --static ]] && return 0
    local newest
    newest=$(objdump -T "$1" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
    if [[ -n $newest && $(printf '%s\nGLIBC_2.41\n' "$newest" | sort -V | tail -1) != GLIBC_2.41 ]]; then
        echo "$1 needs $newest, newer than the guest's glibc 2.41; rebuild with --static" >&2
        exit 1
    fi
}

gcc "${cflags[@]}" "${sources[@]}" -o "$output/ant-torture" "${link[@]}"
check_glibc "$output/ant-torture"
for module in "${modules[@]}"; do
    gcc "${cflags[@]}" -DSINGLE_MODULE="\"$module\"" -DSINGLE_ID_"${module//-/_}" "${sources[@]}" \
        -o "$output/ant-$module" "${link[@]}"
    check_glibc "$output/ant-$module"
done

# Static analysis variants. Their data is generated reproducibly.
generated="$output/.static-zoo"
mkdir -p "$generated/packed" "$generated/huge"
python3 -I - "$generated" <<'EOF'
import gzip, io, random, struct, sys, zipfile, zlib

root = sys.argv[1]

def array(name, data):
    rows = [", ".join(f"0x{b:02x}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return f"static const unsigned char {name}[{len(data)}] = {{\n    " + ",\n    ".join(rows) + "\n};\n"

def png(width, height):
    raw = b"".join(b"\x00" + bytes((x * 7 + y * 3) & 255 for x in range(width * 3)) for y in range(height))
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))

# Packed: a 256 KiB high-entropy block and embedded gzip, ZIP and PNG.
rng = random.Random(0x5EED)
noise = bytes(rng.getrandbits(8) for _ in range(256 * 1024))
text = b"Antinomie static zoo: embedded payload.\n" * 64
buffer = io.BytesIO()
with gzip.GzipFile(filename="zoo.txt", mode="wb", fileobj=buffer, mtime=0) as stream:
    stream.write(text)
archive = io.BytesIO()
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
    info = zipfile.ZipInfo("zoo/readme.txt", date_time=(2026, 1, 1, 0, 0, 0))
    bundle.writestr(info, text)
with open(f"{root}/packed/static-zoo-generated.h", "w") as out:
    out.write("#include <stdint.h>\n#include <stddef.h>\n")
    for name, data in (("zoo_noise", noise), ("zoo_gzip", buffer.getvalue()),
                       ("zoo_zip", archive.getvalue()), ("zoo_png", png(48, 48))):
        out.write(array(name, data))
    out.write("static uint32_t zoo_generated(void)\n{\n    uint32_t hash = 0;\n")
    for name in ("zoo_noise", "zoo_gzip", "zoo_zip", "zoo_png"):
        out.write(f"    for (size_t i = 0; i < sizeof {name}; i += 97) hash = hash * 31 + {name}[i];\n")
    out.write("    return hash;\n}\n")

# Huge: thousands of functions and strings, and hundreds of named sections.
functions, strings, sections = 3000, 2000, 200
with open(f"{root}/huge/static-zoo-generated.h", "w") as out:
    out.write("#include <stdint.h>\n#include <stddef.h>\n")
    for n in range(functions):
        out.write(f"__attribute__((noinline)) uint32_t zoo_function_{n:04d}(uint32_t x) "
                  f"{{ return (x ^ {n * 2654435761 & 0xffffffff}u) * {n | 1}u + {n}u; }}\n")
    out.write("static uint32_t (*const zoo_functions[])(uint32_t) = {\n")
    out.write(",\n".join(f"    zoo_function_{n:04d}" for n in range(functions)) + "\n};\n")
    out.write("static const char *const zoo_strings[] = {\n")
    out.write(",\n".join(f'    "antinomie static zoo string {n:04d} with some readable text"'
                         for n in range(strings)) + "\n};\n")
    for n in range(sections):
        out.write(f'__attribute__((used, section(".ant.zoo.{n:03d}"))) '
                  f'static const char zoo_section_{n:03d}[] = "section {n:03d}";\n')
    out.write("static uint32_t zoo_generated(void)\n{\n    uint32_t hash = 1;\n"
              "    for (size_t i = 0; i < sizeof zoo_functions / sizeof zoo_functions[0]; i++)\n"
              "        hash = zoo_functions[i](hash);\n"
              "    for (size_t i = 0; i < sizeof zoo_strings / sizeof zoo_strings[0]; i++)\n"
              "        hash += (uint32_t)zoo_strings[i][i % 30];\n    return hash;\n}\n")
EOF

zoo="$source_dir/static-zoo.c"
variant() {
    local name=$1
    shift
    gcc -Wall -Wextra "$@" "$zoo" -o "$output/ant-static-$name"
}
variant symbols -O0 -g
variant stripped -O2 -s
variant nopie -O2 -fno-pie -no-pie
variant norelro -O2 -Wl,-z,norelro -Wl,-z,lazy
variant unprotected -O0 -fno-stack-protector -U_FORTIFY_SOURCE -fno-pie -no-pie \
    -Wl,-z,execstack -Wl,--no-warn-execstack -Wl,-z,norelro
variant hardened -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fstack-clash-protection \
    -fcf-protection -fPIE -pie -Wl,-z,relro,-z,now
variant static -O2 -static
variant packed -O2 -DZOO_GENERATED -I"$generated/packed"
variant huge -O1 -DZOO_GENERATED -I"$generated/huge"
for file in "$output"/ant-static-*; do
    [[ $file == *-static ]] || check_glibc "$file"
done
rm -rf "$generated"

echo "built in $output:"
(cd "$output" && ls -1 ant-* | sed 's/^/  /')
