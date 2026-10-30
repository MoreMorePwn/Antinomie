#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Prerequisites in a disposable benign-test VM with NAT; never on the host.
set -eu
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin DEBIAN_FRONTEND=noninteractive
setup_exit() {
    setup_status=$?
    if test "$setup_status" -ne 0; then
        tail -60 /tmp/module-abi-apt.log
    fi
    exit "$setup_status"
}
trap setup_exit EXIT
apt-get update -q > /tmp/module-abi-apt.log 2>&1
apt-get install -y -q make gcc bpftrace \
    /dev/shm/linux-headers-6.12.94+deb13-amd64_6.12.94-1_amd64.deb \
    /dev/shm/linux-headers-6.12.94+deb13-common_6.12.94-1_all.deb \
    /dev/shm/linux-kbuild-6.12.94+deb13_6.12.94-1_amd64.deb >> /tmp/module-abi-apt.log 2>&1
make -C "/lib/modules/$(uname -r)/build" M=/tmp -j2 modules
modinfo /tmp/module_fixture.ko
printf 'OOT-BUILD-PASS\nSTEALTH-END\n'
