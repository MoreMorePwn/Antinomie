#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run only inside a disposable Debian qualification VM, as root.
set -eu
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
uname -a
cat /proc/version
cat /sys/kernel/security/lsm; echo
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
printf 'PASS systemd filesystem restriction enforced\n'
# systemd attached bpf-restrict-fs at boot: no "BPF LSM is not available"
# (or other failure) line, which would also give the kernel away.
journalctl -b -o cat --no-pager | grep -v module-abi | \
    grep -Ei 'bpf.?lsm|bpf-restrict-fs|restrict.?file.?system' \
    > /tmp/module-abi-bpf-lsm.log || true
cat /tmp/module-abi-bpf-lsm.log
if grep -Eqi 'not available|not supported|fail|error' /tmp/module-abi-bpf-lsm.log; then
    printf 'FAIL systemd reported a BPF LSM problem at boot\n'
    exit 1
fi
printf 'PASS no BPF LSM failure in the boot journal\n'
# grub-pc's debconf answer names this VM's own disk (BIOS installations).
if test -d /usr/lib/grub/i386-pc; then
    device=$(debconf-show grub-pc | sed -n 's/^[* ]*grub-pc\/install_devices: //p')
    printf 'grub-pc install device: %s\n' "$device"
    test -b "$device"
    printf 'PASS grub-pc names an existing disk\n'
fi
printf 'ABI-CHECK-PASS\nSTEALTH-END\n'
