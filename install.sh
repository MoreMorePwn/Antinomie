#!/usr/bin/env bash
#
# install.sh — install Antinomie for the current user (no root needed):
#   ~/.local/bin/antinomie                                  the app
#   ~/.local/share/applications/antinomie.desktop           application menu entry
#   ~/.local/share/icons/hicolor/scalable/apps/antinomie.svg icon
#
#   ./install.sh               build (if needed) and install or update
#   ./install.sh --uninstall   remove those three files (application data stays)
#
# QEMU (qemu-system-x86_64, qemu-img) and KVM access are still needed to run VMs.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
bin="$HOME/.local/bin/antinomie"
desktop="$data/applications/antinomie.desktop"
icon="$data/icons/hicolor/scalable/apps/antinomie.svg"

refresh_menus() {
    command -v update-desktop-database >/dev/null && update-desktop-database -q "$data/applications" || true
    command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$data/icons/hicolor" 2>/dev/null || true
}

if [[ ${1:-} == --uninstall ]]; then
    rm -f "$bin" "$desktop" "$icon"
    refresh_menus
    echo "Antinomie removed. Its bases, VM disks and recordings (~/antinomie by default) are kept."
    exit 0
elif [[ $# -gt 0 ]]; then
    echo "usage: $0 [--uninstall]" >&2
    exit 2
fi

bash "$repo/scripts/build-monitor-host.sh" >/dev/null
install -D -m 0755 "$repo/work/monitor-host/antinomie-monitor" "$bin"
install -D -m 0644 "$repo/src/antinomie/monitor/assets/antinomie.svg" "$icon"
mkdir -p "$(dirname "$desktop")"
sed "s|@BIN@|$bin|" "$repo/src/antinomie/monitor/assets/antinomie.desktop" > "$desktop"
chmod 0644 "$desktop"
refresh_menus
echo "Installed: $bin"
echo "Start it from the application menu (Antinomie) or run: antinomie"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "Note: ~/.local/bin is not on PATH; add it or start Antinomie from the menu." ;;
esac
