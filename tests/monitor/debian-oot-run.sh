#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
trap 'rmmod module_fixture 2>/dev/null || true' EXIT
insmod /root/module_fixture.ko
cat /proc/module_fixture
grep '^module_fixture ' /proc/modules
rmmod module_fixture
test ! -e /proc/module_fixture
# This unsigned out-of-tree fixture may taint the kernel; Debian modules were
# checked for no taint before it was loaded.
printf 'Taint after unsigned fixture: '
cat /proc/sys/kernel/tainted
if ! timeout 60 bpftrace -c '/usr/bin/cat /etc/os-release' \
    -e 'fentry:vmlinux:vfs_read /pid == cpid/ { @reads = count(); }' \
    > /tmp/module-abi-fentry.log 2>&1; then
    cat /tmp/module-abi-fentry.log
    exit 1
fi
cat /tmp/module-abi-fentry.log
grep -Eq '^@reads: [1-9][0-9]*$' /tmp/module-abi-fentry.log
printf 'OOT-RUN-PASS\nSTEALTH-END\n'
