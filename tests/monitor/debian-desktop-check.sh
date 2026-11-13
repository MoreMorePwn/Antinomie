#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run only inside a disposable Debian desktop qualification VM, as root
# (vm-regress.py's desktop check): the desktop comes up as the base promises.
# usage: debian-desktop-check [SECONDS]  (how long to wait for the greeter)
# Prints DESKTOP-CHECK-PASS at the end. On a failure it prints
# DESKTOP-CHECK-FAIL with the reason and keeps running, so the harness's wait
# for the marker fails the check with this output.
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
limit=${1:-600}
fail() {
    printf 'DESKTOP-CHECK-FAIL %s\n' "$*"
    exec sleep 36000
}
pass() {
    printf 'PASS %s\n' "$*"
}
# Wait until the shell test $1 holds, at most until $limit seconds of uptime.
wait_for() {
    while ! sh -c "$1" >/dev/null 2>&1; do
        up=$(cut -d. -f1 /proc/uptime)
        [ "$up" -lt "$limit" ] || return 1
        sleep 2
    done
}
cat /proc/version
cat /proc/cmdline
release=$(uname -r)
# The kernel's banner is Debian's own, and Debian's kernel packages are
# installed as Debian shipped them.
grep -q "Debian 6.12.94-1 " /proc/version || fail "the banner is not Debian's 6.12.94-1"
case $release in
*+deb13-*) ;;
*) fail "kernel release $release is not Debian 13's" ;;
esac
dpkg-query -W -f='${db:Status-Status}\n' "linux-image-$release" | grep -qx installed ||
    fail "linux-image-$release is not installed"
test -z "$(dpkg --verify "linux-image-$release")" || fail "dpkg --verify reports Debian's kernel package"
pass "Debian banner and kernel package linux-image-$release"
test -e /sys/kernel/btf/vmlinux || fail "no vmlinux BTF"
pass "vmlinux BTF"
# The command line names the serial console and panic=-1 (user decision 2026-11-13).
grep -Eq '(^| )console=tty(S0|AMA0)( |$)' /proc/cmdline || fail "no serial console on the command line"
grep -Eq '(^| )panic=-1( |$)' /proc/cmdline || fail "no panic=-1 on the command line"
pass "serial console and panic=-1 on the command line"
manager=$(cat /etc/X11/default-display-manager 2>/dev/null) || fail "no default display manager"
manager=${manager##*/}
test "$(systemctl get-default)" = graphical.target || fail "the default target is not graphical.target"
# The display manager shows its greeter: a greeter session on seat0.
greeter() {
    for session in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
        if [ "$(loginctl show-session "$session" -p Class --value)" = greeter ]; then
            printf '%s\n' "$session"
            return 0
        fi
    done
    return 1
}
wait_for "systemctl is-active --quiet display-manager" ||
    fail "$manager is not active after $limit s ($(systemctl is-active display-manager))"
pass "display manager $manager active"
session=
while [ -z "$session" ]; do
    session=$(greeter) && break
    session=
    [ "$(cut -d. -f1 /proc/uptime)" -lt "$limit" ] || fail "no greeter session after $limit s"
    sleep 2
done
printf 'greeter after %s s of uptime\n' "$(cut -d' ' -f1 /proc/uptime)"
loginctl show-session "$session" -p Class -p Type -p Seat -p Service -p State
test "$(loginctl show-session "$session" -p Seat --value)" = seat0 || fail "the greeter is not on seat0"
pass "greeter session $session of $manager"
if [ "$manager" = gdm3 ]; then
    wait_for "pgrep -x gnome-shell" || fail "no gnome-shell for the GDM greeter"
    pass "gnome-shell runs the greeter"
fi
# The display: virtio_gpu is Debian's module, loaded by udev (no load list,
# not built in), and drives a connected, enabled connector.
grep -q '^virtio_gpu ' /proc/modules || fail "virtio_gpu is not loaded as a module"
if grep -q 'virtio_gpu' "/lib/modules/$release/modules.builtin" 2>/dev/null; then
    fail "virtio_gpu is built in"
fi
if grep -rqs '^[[:space:]]*virtio[_-]gpu' /etc/modules /etc/modules-load.d /usr/lib/modules-load.d; then
    fail "virtio_gpu is in a module load list"
fi
pass "virtio_gpu a module loaded by udev"
connected=
for connector in /sys/class/drm/card*-*; do
    [ -e "$connector/status" ] || continue
    if [ "$(cat "$connector/status")" = connected ] && [ "$(cat "$connector/enabled")" = enabled ]; then
        connected=${connector##*/}
        printf 'connector %s modes %s\n' "$connected" "$(head -n 1 "$connector/modes")"
    fi
done
test -n "$connected" || fail "no connected, enabled display connector"
pass "display connector $connected"
# Every loaded module is Debian's, signed, and the kernel is untainted.
count=0
for module in $(awk '{print $1}' /proc/modules); do
    signer=$(modinfo -F signer "$module" 2>/dev/null)
    test -n "$signer" || fail "module $module is not signed"
    test -z "$(cat "/sys/module/$module/taint" 2>/dev/null)" || fail "module $module taints the kernel"
    count=$((count + 1))
done
test "$(cat /proc/sys/kernel/tainted)" -eq 0 || fail "the kernel is tainted ($(cat /proc/sys/kernel/tainted))"
pass "$count loaded modules all signed and untainted, taint 0"
systemctl --failed --no-legend --plain || true
printf 'DESKTOP-CHECK-PASS\n'
