#!/bin/sh
# GRUB as the installer's grub-installer sets it up on this VM's disk, run in
# the guest by provisioning. usage: boot_loader.sh bios|uefi DISK
# DISK is the VM's disk as the guest names it (/dev/vda on virtio).
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
set -eu
case $1 in
bios)
    # grub-install --force writes the boot code into the MBR and the gap
    # before the first partition, with /boot/grub/i386-pc beside it (core.img
    # finds this disk's root by its UUID, so every VM gets its own). The
    # appliance names the disk /dev/sda; debconf gets the VM's own name for
    # it, which grub-pc's upgrades install to, as grub-installer leaves it.
    if [ -d /usr/lib/grub/i386-pc ]; then
        grub-install --force /dev/sda >/dev/null 2>&1
        printf 'grub-pc grub-pc/install_devices multiselect %s\ngrub-pc grub-pc/install_devices_empty boolean false\ngrub-pc grub-pc/install_devices_empty seen false\n' "$2" | debconf-set-selections
    fi
    ;;
uefi)
    # The ESP provisioning formatted for this VM: fstab names it, and
    # grub-install puts the shim, GRUB and their fallback copies on it
    # (EFI/debian and, as grub-installer answers for an empty ESP, EFI/BOOT).
    # The firmware's boot entry is the bootstrap initrd's to write.
    esp=$(blkid -s UUID -o value /dev/sda1)
    sed -i -E "s|^UUID=[0-9A-Fa-f-]+([[:space:]]+/boot/efi[[:space:]])|UUID=$esp\1|" /etc/fstab
    grub-install --force --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian \
        --force-extra-removable --no-nvram >/dev/null 2>&1
    ;;
*)
    exit 2
    ;;
esac
if command -v update-grub >/dev/null; then update-grub >/dev/null 2>&1 || true; fi
