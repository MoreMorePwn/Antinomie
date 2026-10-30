#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run only inside a disposable cloud-profile test VM on a Debian base, as
# root. Prints "key value" lines about the machine as a provider's instance
# would show it: the wired interface, virtualization, cloud-init and the
# lived-in state the first start wrote (path, size, age in days).
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
now=$(date +%s)
for link in /sys/class/net/*; do
    name=${link##*/}
    test "$name" = lo && continue
    printf 'iface %s state=%s ipv4=%s\n' "$name" "$(cat "$link/operstate")" \
        "$(ip -4 -o addr show dev "$name" | awk '{print $4}' | head -1)"
done
printf 'virt %s\n' "$(systemd-detect-virt 2>&1)"
if command -v cloud-init >/dev/null; then
    printf 'cloud-init %s\n' "$(cloud-init status 2>&1 | tr '\n' ' ')"
else
    printf 'cloud-init absent\n'
fi
printf 'hostname %s etc=%s\n' "$(hostname)" "$(cat /etc/hostname)"
for path in /var/lib/cloud/data/instance-id /var/lib/cloud/data/result.json \
    /var/lib/cloud/instances/*/datasource /var/lib/cloud/instances/*/boot-finished \
    /etc/cloud/cloud.cfg.d/90_provider.cfg /var/log/cloud-init.log \
    /var/log/cloud-init-output.log /var/log/auth.log /var/log/wtmp \
    /root/.bash_history /home/*/.bash_history; do
    if test -e "$path"; then
        printf 'state %s size=%s age_days=%s\n' "$path" "$(stat -c %s "$path")" \
            "$(( (now - $(stat -c %Y "$path")) / 86400 ))"
    fi
done
printf 'instance-id %s\n' "$(cat /var/lib/cloud/data/instance-id 2>/dev/null)"
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print "user " $1 " " $6 " " $7}'
printf 'last %s\n' "$(last -n 3 2>&1 | head -3 | tr '\n' '|')"
printf 'STEALTH-END\n'
