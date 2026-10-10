# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
#
# Runs a program in the guest's logged-in graphical session. The host launches
# this as `/bin/sh -c SCRIPT antinomie MODE UID PROGRAM [ARGUMENT...]`: the
# program and its arguments stay positional parameters and are never parsed as
# shell text. MODE is `desktop` (exec the program, which keeps the run's root
# process) or `terminal` (open a terminal window on the desktop running it).
# UID is the run's user; its own session is joined, and UID 0 joins a user's.
# Comment-only lines are removed before the script is sent to the guest.
mode=$1 uid=$2
shift 2
sq="'"
names='DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS XDG_SESSION_TYPE XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP DESKTOP_SESSION XDG_DATA_DIRS XDG_CONFIG_DIRS LANG HOME USER LOGNAME SHELL'
# Variables the run's own environment sets keep their values.
pattern= preset=' '
for name in $names; do
	pattern="$pattern${pattern:+|}$name"
	eval "[ -z \"\${$name+set}\" ]" || preset="$preset$name "
done
pattern="^($pattern)="

owner_of() {
	owner=
	[ -r "$1/status" ] || return 0
	while read -r key value rest; do
		if [ "$key" = Uid: ]; then
			owner=$value
			return 0
		fi
	done <"$1/status"
}
eligible() {
	[ -n "$owner" ] || return 1
	[ "$owner" = "$uid" ] && return 0
	[ "$uid" = 0 ] && [ "$owner" -ge 1000 ] && [ "$owner" -lt 65534 ]
}
read_environment() {
	# Preserve trailing newlines so byte counting also detects a cut record.
	environment=$(grep -a -s -z -E "$pattern" "$1" | head -c "$((environment_limit + 1))" | tr '\0' '\n'; printf '.')
	environment=${environment%.}
	size=$(printf '%s' "$environment" | wc -c)
	if [ "$size" -gt "$environment_limit" ]; then
		echo "antinomie: session discovery exceeded its $environment_limit-byte environment limit; the program was not started" >&2
		exit 1
	fi
	case $environment in
	'' | *"$newline") ;;
	*)
		echo "antinomie: session discovery found a truncated environment entry; the program was not started" >&2
		exit 1
		;;
	esac
}

# The session process whose environment names the most of its display wins.
# Limit work to 4096 candidates and retained allowlisted environment to 64 KiB
# per eligible candidate. Ineligible processes never have their environment read.
candidate_limit=4096 environment_limit=65536 candidates=0
newline='
'
best_score=0 best_owner= session=
for candidate in /proc/[0-9]*; do
	[ -d "$candidate" ] || continue
	candidates=$((candidates + 1))
	if [ "$candidates" -gt "$candidate_limit" ]; then
		echo "antinomie: session discovery exceeded its $candidate_limit-process candidate limit; the program was not started" >&2
		exit 1
	fi
	[ "$candidate" != "/proc/$$" ] || continue
	owner_of "$candidate"
	eligible || continue
	read_environment "$candidate/environ"
	score=0 display=0
	while IFS= read -r entry; do
		case $entry in
		DISPLAY=?* | WAYLAND_DISPLAY=?*) display=1 score=$((score + 2)) ;;
		XAUTHORITY=?* | DBUS_SESSION_BUS_ADDRESS=?* | XDG_RUNTIME_DIR=?*) score=$((score + 1)) ;;
		esac
	done <<EOF
$environment
EOF
	if [ "$display" = 1 ] && [ "$score" -gt "$best_score" ]; then
		session=$environment best_score=$score best_owner=$owner
	fi
done

if [ -z "$best_owner" ]; then
	if [ "$uid" = 0 ]; then
		echo "antinomie: no graphical session is logged in on the guest; log in on the VM display, then run the program again" >&2
	else
		echo "antinomie: UID $uid has no graphical session on the guest; log in as that user on the VM display, then run the program again" >&2
	fi
	exit 1
fi
while IFS= read -r entry; do
	name=${entry%%=*}
	case " $names " in
	*" $name "*) ;;
	*) continue ;;
	esac
	case $preset in
	*" $name "*) continue ;;
	esac
	case $name in
	HOME | USER | LOGNAME | SHELL) [ "$best_owner" = "$uid" ] || continue ;;
	esac
	export "$entry"
done <<EOF
$session
EOF
if [ -z "${XDG_RUNTIME_DIR-}" ] && [ -d "/run/user/$best_owner" ]; then
	export XDG_RUNTIME_DIR="/run/user/$best_owner"
fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS-}" ] && [ -S "${XDG_RUNTIME_DIR-}/bus" ]; then
	export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
fi
printf 'antinomie: joined the graphical session of UID %s (%s)\n' "$best_owner" \
	"${WAYLAND_DISPLAY:+WAYLAND_DISPLAY=$WAYLAND_DISPLAY }${DISPLAY:+DISPLAY=$DISPLAY}" >&2

if [ "$mode" = desktop ]; then
	exec "$@"
fi

# Terminal: the window stays open after the program exits until Enter.
quote_all() {
	quoted=
	for word; do
		rest=$word out=
		while :; do
			case $rest in
			*"$sq"*)
				out="$out${rest%%"$sq"*}$sq\\$sq$sq"
				rest=${rest#*"$sq"}
				;;
			*) break ;;
			esac
		done
		quoted="$quoted${quoted:+ }$sq$out$rest$sq"
	done
}
outside() {
	printf 'antinomie: %s may run the program in a separate terminal server, outside this run; Capture All still records it\n' "$1" >&2
}
gnome_terminal() {
	# A private terminal server started here keeps the program in this run.
	app=org.gnome.Terminal.Antinomie$$
	/usr/libexec/gnome-terminal-server --app-id "$app" &
	server=$!
	if command -v gdbus >/dev/null 2>&1; then
		if ! gdbus wait --session --timeout 15 "$app"; then
			kill "$server" 2>/dev/null
			echo "antinomie: the guest terminal server did not start" >&2
			return 1
		fi
	else
		sleep 2
	fi
	gnome-terminal --app-id "$app" --wait -- "$@"
	status=$?
	kill "$server" 2>/dev/null
	wait "$server" 2>/dev/null
	return "$status"
}
hold='"$@"; status=$?; printf "\n[%s exited with status %s; press Enter to close]" "$1" "$status"; read -r _; exit "$status"'
set -- /bin/sh -c "$hold" antinomie "$@"
if command -v xfce4-terminal >/dev/null 2>&1; then
	xfce4-terminal --disable-server -x "$@"
elif command -v mate-terminal >/dev/null 2>&1; then
	mate-terminal --disable-factory -x "$@"
elif command -v konsole >/dev/null 2>&1; then
	konsole --separate -e "$@"
elif command -v qterminal >/dev/null 2>&1; then
	qterminal -e "$@"
elif command -v lxterminal >/dev/null 2>&1; then
	quote_all "$@"
	lxterminal --no-remote -e "$quoted"
elif command -v gnome-terminal >/dev/null 2>&1 && [ -x /usr/libexec/gnome-terminal-server ]; then
	gnome_terminal "$@"
elif [ -n "${DISPLAY-}" ] && command -v xterm >/dev/null 2>&1; then
	xterm -e "$@"
elif command -v x-terminal-emulator >/dev/null 2>&1; then
	outside x-terminal-emulator
	x-terminal-emulator -e "$@"
else
	echo "antinomie: the guest has no terminal emulator (xfce4-terminal, mate-terminal, konsole, qterminal, lxterminal, gnome-terminal, xterm or x-terminal-emulator)" >&2
	exit 127
fi
