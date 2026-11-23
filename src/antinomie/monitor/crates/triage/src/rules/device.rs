// SPDX-License-Identifier: GPL-3.0-only
//! Rules for what an IoT bot does to the device it lands on: it disables the
//! watchdog (so the device does not reboot once the program that fed it is
//! gone), kills the services on the ports it wants and binds them itself, and
//! changes the firewall without a command line (iptables' own socket option).
//! Writing or erasing the flash is `impact.block_device_write` (paths).
use super::ctx::Ctx;
use super::state::State;
use super::Hit;

pub const NS: u64 = 1_000_000_000;
/// A port bound this long after the run killed a process it did not start
/// counts as taken from that process.
pub const TAKEOVER_SPAN: u64 = 60 * NS;
/// Ports a device's services hold and bots take over, besides every port
/// below 1024: telnet's alternates, the TR-069 and web ports of routers, ADB,
/// the camera makers' vendor ports (Xiongmai 34567, Dahua 37777, Hikvision
/// 8000) and HiSilicon's debug port.
pub const SERVICE_PORTS: &[u16] = &[
    2323, 5555, 7547, 8000, 8080, 8081, 8443, 8888, 9000, 9527, 34567, 37777,
];
/// WDIOC_SETOPTIONS (WDIOS_DISABLECARD turns the watchdog off), WDIOC_SETTIMEOUT
/// and WDIOC_SETPRETIMEOUT.
const WATCHDOG_IOCTLS: &[(u64, &str)] = &[
    (0x8004_5704, "WDIOC_SETOPTIONS"),
    (0xc004_5706, "WDIOC_SETTIMEOUT"),
    (0xc004_5708, "WDIOC_SETPRETIMEOUT"),
];
/// IPT_SO_SET_REPLACE and IP6T_SO_SET_REPLACE (level SOL_IP 0, SOL_IPV6 41):
/// the call that replaces a whole iptables table, as iptables-legacy commits
/// every change.
const SET_REPLACE: u64 = 64;

/// The watchdog devices bots try: `/dev/watchdog`, `/dev/watchdogN`,
/// `/dev/misc/watchdog`, and the FTWDT101 watchdog of some cameras that
/// Mirai's forks add (`/dev/FTWDT101_watchdog`, `/dev/FTWDT101 watchdog`).
pub fn is_watchdog(path: &str) -> bool {
    matches!(
        path,
        "/dev/misc/watchdog" | "/dev/FTWDT101_watchdog" | "/dev/FTWDT101 watchdog"
    ) || path
        .strip_prefix("/dev/watchdog")
        .is_some_and(|rest| rest.is_empty() || rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Each action on the watchdog (open, ioctl, magic close) is a row of its own.
/// A failed open for writing is a row too, one tier lower: a sandbox has no
/// watchdog device, so a bot's attempt (Mirai tries `/dev/watchdog`, then
/// `/dev/misc/watchdog`, then its forks' vendor names) fails with ENOENT and
/// was not reported before (T0600 run 5015e226 tried six such paths).
pub fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    match cx.name {
        "open" | "openat" | "openat2" if cx.opens_for_write() => {
            if let Some(path) = cx
                .touches()
                .iter()
                .map(|touch| touch.path.as_str())
                .find(|path| is_watchdog(path))
            {
                let hit = if cx.ok {
                    Hit::new(
                        "evasion.watchdog_disable",
                        path,
                        format!("{} opens the watchdog device {path}", cx.name),
                    )
                    .detail("Opening the watchdog takes it over: from then on the device reboots unless this process feeds it, closes it with the magic character or turns it off.")
                } else {
                    Hit::new(
                        "evasion.watchdog_disable",
                        path,
                        format!(
                            "{} tries to open the watchdog device {path} for writing and fails",
                            cx.name
                        ),
                    )
                    .detail("The device is not there or not allowed. A program that tries to take over the watchdog means to stop the device from rebooting once it kills the program that fed it, as IoT bots do.")
                };
                out.push(hit);
            }
        }
        "ioctl" => watchdog_ioctl(cx, out),
        "write" if cx.ok => {
            if let Some(path) = cx.fd_path(cx.args[0]).filter(|path| is_watchdog(path))
                && cx.payload(false).contains(&b'V')
            {
                out.push(Hit::new(
                    "evasion.watchdog_disable",
                    format!("{path} magic close"),
                    format!("write of the magic close character V to {path}"),
                ));
            }
        }
        "bind" => takeover(cx, st, out),
        "setsockopt" if cx.ok && matches!(cx.args[1], 0 | 41) && cx.args[2] == SET_REPLACE => {
            let family = if cx.args[1] == 0 {
                "iptables"
            } else {
                "ip6tables"
            };
            out.push(Hit::new(
                "evasion.firewall_modify",
                family,
                format!("setsockopt replaces an {family} table (the legacy firewall's commit)"),
            ));
        }
        _ => {}
    }
}

fn watchdog_ioctl(cx: &Ctx, out: &mut Vec<Hit>) {
    let Some(path) = cx.fd_path(cx.args[0]).filter(|path| is_watchdog(path)) else {
        return;
    };
    let Some((_, name)) = WATCHDOG_IOCTLS
        .iter()
        .find(|(request, _)| *request == cx.args[1])
    else {
        return;
    };
    let what = if *name == "WDIOC_SETOPTIONS" {
        "turns the watchdog off or on (WDIOS_DISABLECARD)"
    } else {
        "changes how long the watchdog waits before it reboots the device"
    };
    out.push(Hit::new(
        "evasion.watchdog_disable",
        format!("{path} {name}"),
        format!("ioctl {name} on {path} {what}"),
    ));
}

/// Remembered by the kill rule: a process the run did not start was sent
/// SIGKILL or SIGTERM.
pub fn killed(st: &mut State, time: u64, pid: u32) {
    st.foreign_kills.push(time, TAKEOVER_SPAN, pid);
}

/// A TCP port a service holds, bound soon after the run killed a process it did
/// not start.
fn takeover(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if !cx.ok {
        return;
    }
    let Some((ip, port)) = cx.address(1).as_ref().and_then(super::network::parse) else {
        return;
    };
    let stream = cx
        .socket(cx.args[0])
        .is_some_and(|socket| !socket.is_datagram());
    if !stream || port == 0 || ip.is_loopback() || !(port < 1024 || SERVICE_PORTS.contains(&port)) {
        return;
    }
    let now = cx.time();
    let victims: Vec<String> = st
        .foreign_kills
        .items_since(now, TAKEOVER_SPAN)
        .map(u32::to_string)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if victims.is_empty() || !st.taken_ports.insert(port) {
        return;
    }
    out.push(
        Hit::new(
            "impact.service_takeover",
            format!("tcp {port}"),
            format!(
                "bind to TCP {ip}:{port} within a minute after the run killed pid{} {}",
                if victims.len() == 1 { "" } else { "s" },
                victims.join(", ")
            ),
        )
        .detail("A process the run did not start was killed and the run then bound a service port. IoT bots kill the device's telnet, SSH and web services this way and hold their ports so that no one, including a rival bot or the owner, can log in again."),
    );
}
