#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# check-sample-branding.sh — the behaviour samples carry no product name.
#
#   usage: tests/monitor/check-sample-branding.sh [OUTPUT_DIR]
#
# Builds the behaviour samples (static, as the guests run them) into OUTPUT_DIR
# (a scratch directory when omitted) and fails when any built binary holds the
# text "antinom" in any case, DWARF paths included.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output=${1:-}
if [[ -z $output ]]; then
    output=$(mktemp -d)
    trap 'rm -rf "$output"' EXIT
fi
"$here/build-behavior-samples.sh" "$output"
checked=0
failed=0
for file in "$output"/demo-*; do
    [[ -f $file && -x $file ]] || continue
    checked=$((checked + 1))
    if strings -a "$file" | grep -i antinom >/dev/null; then
        echo "$file holds the product name:" >&2
        strings -a "$file" | grep -i antinom | head -5 >&2
        failed=$((failed + 1))
    fi
done
if [[ $checked -eq 0 ]]; then
    echo "no behaviour sample was built" >&2
    exit 1
fi
if [[ $failed -ne 0 ]]; then
    exit 1
fi
echo "$checked behaviour samples hold no product name"
