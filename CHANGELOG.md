# Changelog

All notable changes to Antinomie. Versions follow semantic versioning; see
[CONTRIBUTING.md](CONTRIBUTING.md#12-versioning). Each version names the guest
contract revision its kernel patches implement.

## 0.2.0 — in development

Guest contract revision 11 (kernel patch series `0001`–`0016`).

- Opt-in static analysis of guest executables with a structured analysis
  workspace.
- Independent guest process attachment, process tree and global capture.
- Revamped interface (in progress).

## 0.1.0 — 2026-10-08

Guest contract revision 9 (kernel patch series `0001`–`0013`).

- QEMU VM monitor with a patched Linux 6.12.94 guest kernel that records
  native x86-64 system calls, their arguments and asynchronous I/O over a
  shared-memory transport (ABI 7).
- Dockable workspace: VMs, bases, runs, paired syscall trace, terminals,
  per-VM history and storage locations.
- Bases: download (checksum-verified catalog), import, and the **Build base**
  wizard: installer-style questions (base, build mode, language, keyboard,
  time zone, hostname, Debian desktop, software, mirror and proxy), built on
  this Linux host or in a QEMU builder VM, with a cached kernel per patch
  series.
- Bases record their kernel's contract revision, the app version that built
  them and the oldest app version that can run them; the running guest
  kernel is checked against its base.
- Guest RAM up to 8 GiB (regions above 4 GiB mapped).
- `./run.sh` and per-user `./install.sh` (command, menu entry, icon).
- Syscall trace rows colored by category (eleven groups covering all 375
  native syscalls) with a category filter; failed calls marked in red.
- Debian builds offer the installer's desktops (GNOME, Xfce, GNOME
  Flashback, KDE Plasma, Cinnamon, MATE, LXDE, LXQt) and a base name.
- Prebuilt bases for this version: BusyBox `312bfe10…` and Debian 13
  (GNOME) `64953c89…` on the Hugging Face bucket
  `MoreMorePwn/antinomie-bases`.
