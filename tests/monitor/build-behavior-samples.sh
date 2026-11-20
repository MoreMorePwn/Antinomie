#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# build-behavior-samples.sh — build the behavior samples.
#
#   usage: tests/monitor/build-behavior-samples.sh OUTPUT_DIR [--dynamic]
#
# CC picks the compiler (default gcc; aarch64-linux-gnu-gcc for arm64 guests).
#
# Writes OUTPUT_DIR/demo-all (every scenario), OUTPUT_DIR/demo-090 (only the
# scenarios of the 0.9.0 features) and one demo-<scenario> per scenario.
# Static by default, so the samples run on the BusyBox and minimal guests;
# --dynamic links glibc like the default workload build. The preload-lib
# scenario carries a small library and a dynamic child of its own (built here
# with the same compiler, always dynamic: a preload needs the loader).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_dir="$here/behavior-samples"
output=${1:?usage: build-behavior-samples.sh OUTPUT_DIR [--dynamic]}
mode=${2:-}
mkdir -p "$output"
output=$(cd "$output" && pwd)

link=(-static)
case $mode in
    "") ;;
    --dynamic) link=() ;;
    *)
        echo "unknown option $mode" >&2
        exit 2
        ;;
esac

cflags=(-O2 -g -Wall -Wextra -D_GNU_SOURCE -I"$source_dir"
        -ffile-prefix-map="$source_dir"=samples -ffile-prefix-map="$PWD"=.)
# Everything but main.c is compiled once; main.c carries the scenario choice.
shared=(common net evade beaconing discovery probes anti-analysis stage credential-access impact
        iot process-tricks)
objects=$(mktemp -d)
trap 'rm -rf "$objects"' EXIT
for name in "${shared[@]}"; do
    "${CC:-gcc}" "${cflags[@]}" -c "$source_dir/$name.c" -o "$objects/$name.o"
done
# The preloaded library and its dynamic child, embedded as data (preload-lib).
payload_flags=(-O2 -g0 -s -Wall -Wextra -D_GNU_SOURCE -ffile-prefix-map="$source_dir"=samples)
mkdir -p "$objects/payload"
"${CC:-gcc}" "${payload_flags[@]}" -shared -fPIC "$source_dir/payload/preload-lib.c" \
    -o "$objects/payload/preload-lib.so"
"${CC:-gcc}" "${payload_flags[@]}" "$source_dir/payload/preload-child.c" -o "$objects/payload/preload-child"
{
    echo '    .section .rodata.sample_preload,"a"'
    for blob in lib:preload-lib.so child:preload-child; do
        symbol=sample_preload_${blob%%:*}
        printf '    .balign 16\n    .globl %s\n    .type %s, %%object\n%s:\n' "$symbol" "$symbol" "$symbol"
        printf '    .incbin "%s"\n' "$objects/payload/${blob#*:}"
        printf '    .globl %s_end\n%s_end:\n' "$symbol" "$symbol"
    done
    echo '    .section .note.GNU-stack,"",%progbits'
} > "$objects/payload/blobs.S"
"${CC:-gcc}" -c "$objects/payload/blobs.S" -o "$objects/preload-blobs.o"
link_all() { # SCENARIO-OR-EMPTY OUTPUT [SET]
    local define=()
    [[ -n $1 ]] && define=(-DSINGLE_SCENARIO="\"$1\"")
    [[ -n ${3:-} ]] && define=(-DSCENARIO_SET="\"$3\"")
    "${CC:-gcc}" "${cflags[@]}" "${define[@]}" "$source_dir/main.c" "$objects"/*.o -o "$2" "${link[@]}" -lm
}
link_all "" "$output/demo-all"
link_all "" "$output/demo-090" 0.9.0
# The registry in main.c is the list of scenarios; build one binary for each.
list_scenarios() {
    if "$output/demo-all" --list 2>/dev/null; then
        return
    fi
    # A cross build does not run here: list them with a host build.
    local sources=("$source_dir/main.c") name
    for name in "${shared[@]}"; do sources+=("$source_dir/$name.c"); done
    mkdir -p "$objects/host"
    gcc "${cflags[@]}" "${sources[@]}" -o "$objects/host/demo-all" -lm
    "$objects/host/demo-all" --list
}
mapfile -t scenarios < <(list_scenarios | awk -F'\t' '!/^#/ {print $1}')
if [[ ${#scenarios[@]} -eq 0 ]]; then
    echo "demo-all --list printed no scenarios" >&2
    exit 1
fi
for scenario in "${scenarios[@]}"; do
    link_all "$scenario" "$output/demo-$scenario"
done

if [[ ${#link[@]} -gt 0 ]]; then
    for file in "$output"/demo-* "$output/demo-all"; do
        if readelf -lW "$file" | grep -q INTERP; then
            echo "$file is dynamically linked; rebuild statically" >&2
            exit 1
        fi
    done
fi

echo "built in $output:"
(cd "$output" && ls -1 demo-* | sed 's/^/  /')
