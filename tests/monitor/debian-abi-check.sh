#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run only inside a disposable Debian qualification VM, as root.
set -eu
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
uname -a
cat /proc/version
cat /sys/kernel/security/lsm
lsmod
before=$(cat /proc/sys/kernel/tainted)
test "$before" -eq 0
for module in btrfs xfs nf_tables nft_ct ccm serpent_generic; do
    modprobe "$module"
    signer=$(modinfo -F signer "$module")
    test -n "$signer"
    test -z "$(cat "/sys/module/$module/taint")"
    test -e "/sys/kernel/btf/$module"
    printf 'PASS signed module %s signer=%s\n' "$module" "$signer"
done
test "$(cat /proc/sys/kernel/tainted)" -eq "$before"
mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing
test "$(wc -l < /sys/kernel/tracing/available_filter_functions)" -gt 0
if grep -Ei '^_*antc?_|antinomie' /sys/kernel/tracing/available_filter_functions; then
    exit 1
fi
printf 'PASS tracefs has no recorder functions\n'
test "$(stat -f -c %T /run)" = tmpfs
printf 'readable outside restricted service\n' > /run/module-abi-probe
cat /run/module-abi-probe
if systemd-run --quiet --unit=module-abi-restrict --wait --pipe \
    --property='RestrictFileSystems=~tmpfs' /usr/bin/cat /run/module-abi-probe \
    > /tmp/module-abi-restrict.log 2>&1; then
    cat /tmp/module-abi-restrict.log
    printf 'FAIL filesystem restriction was not enforced\n'
    exit 1
fi
cat /tmp/module-abi-restrict.log
grep -Eq '^cat: /run/module-abi-probe: (Permission denied|Operation not permitted)$' \
    /tmp/module-abi-restrict.log
systemctl reset-failed module-abi-restrict.service
rm /run/module-abi-probe
printf 'PASS systemd filesystem restriction enforced\nABI-CHECK-PASS\nSTEALTH-END\n'
