// SPDX-License-Identifier: GPL-3.0-only
//! The classification: one entry per rule id, with its tier, category and
//! ATT&CK ids. Ids were checked against ATT&CK v20 (a `DET` id is a detection
//! strategy). A technique that ATT&CK lists under two tactics appears once.
use super::{Category as C, Tier as T};

mod behaviour;
mod evasion;

#[derive(Clone, Copy)]
pub struct Spec {
    pub id: &'static str,
    /// Bumped when a rule's trigger or tier changes.
    pub version: u16,
    pub tier: T,
    pub category: C,
    /// Technique and detection-strategy ids; empty when ATT&CK has none.
    pub attack: &'static [&'static str],
    /// A failed call keeps the tier: the failing is the signal.
    pub signal: bool,
    /// Programs that do this as their job. A match lowers the tier by one.
    pub allow: &'static [&'static str],
}

pub const fn rule(
    id: &'static str,
    version: u16,
    tier: T,
    category: C,
    attack: &'static [&'static str],
) -> Spec {
    Spec {
        id,
        version,
        tier,
        category,
        attack,
        signal: false,
        allow: &[],
    }
}

impl Spec {
    pub const fn signal(mut self) -> Self {
        self.signal = true;
        self
    }

    pub const fn allow(mut self, allow: &'static [&'static str]) -> Self {
        self.allow = allow;
        self
    }

    /// The `Source` column: where the classification comes from.
    pub fn source(&self, attack: &[&str]) -> String {
        if attack.is_empty() {
            "Observed behaviour; no ATT&CK technique".into()
        } else {
            format!("MITRE ATT&CK {}", attack.join(" · "))
        }
    }
}

pub fn spec(id: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.id == id)
}

/// Package managers and archive tools, which set times and replace system files on purpose.
pub const PACKAGERS: &[&str] = &[
    "dpkg",
    "apt",
    "apt-get",
    "aptitude",
    "rpm",
    "dnf",
    "yum",
    "zypper",
    "pacman",
    "apk",
    "snap",
    "tar",
    "cp",
    "rsync",
    "install",
    "unattended-upgr",
];
/// Programs that read the credential stores for authentication.
pub const AUTH: &[&str] = &[
    "unix_chkpwd",
    "passwd",
    "chpasswd",
    "su",
    "sudo",
    "login",
    "sshd",
    "sshd-session",
    "pam_unix",
    "vipw",
    "chage",
    "useradd",
    "usermod",
    "userdel",
    "adduser",
    "groupadd",
    "cron",
    "systemd-logind",
    "polkitd",
];
pub const SSH_TOOLS: &[&str] = &[
    "ssh",
    "ssh-agent",
    "ssh-add",
    "sshd",
    "sshd-session",
    "scp",
    "sftp",
];
pub const JIT: &[&str] = &[
    "java",
    "node",
    "nodejs",
    "dotnet",
    "mono",
    "mono-sgen",
    "luajit",
    "pypy",
    "pypy3",
    "qemu-system-x86_64",
];
/// Programs that listen on the wire or ask for an address.
pub const CAPTURE: &[&str] = &[
    "tcpdump",
    "tshark",
    "dumpcap",
    "dhclient",
    "dhcpcd",
    "NetworkManager",
    "systemd-networkd",
    "wpa_supplicant",
    "ping",
    "arping",
];
/// Programs that rebuild the linker cache and library paths as their job.
pub const LINKER: &[&str] = &[
    "ldconfig", "dpkg", "apt", "apt-get", "rpm", "dnf", "yum", "pacman", "apk",
];
pub const SERVICES: &[&str] = &[
    "systemd",
    "dbus-daemon",
    "dbus-broker-launch",
    "systemd-logind",
];

const EARLY: &[Spec] = &[
    // Execution
    rule("process.exec", 2, T::Info, C::Execution, &[]),
    rule("process.crashed_at_start", 1, T::Low, C::Execution, &[]),
    rule("process.no_calls_before_stop", 1, T::Low, C::Execution, &[]),
    rule(
        "process.interpreter",
        2,
        T::Low,
        C::Execution,
        &["T1059.004", "DET0384"],
    ),
    rule(
        "execution.download_cradle",
        1,
        T::Medium,
        C::Execution,
        &["T1105", "DET0060", "T1059.004"],
    ),
    rule(
        "execution.dropped_exec",
        1,
        T::High,
        C::Execution,
        &["T1105", "DET0060"],
    ),
    rule(
        "execution.chmod_exec_temp",
        1,
        T::Medium,
        C::Execution,
        &["T1222.002", "DET0351"],
    ),
    rule(
        "execution.temp_exec",
        1,
        T::Medium,
        C::Execution,
        &["T1027.011", "DET0344", "T1564.001", "DET0032"],
    ),
    rule(
        "execution.compile_then_run",
        1,
        T::Medium,
        C::Execution,
        &["T1027.004", "DET0501"],
    ),
    rule(
        "process.memfd_exec",
        2,
        T::High,
        C::Execution,
        &["T1620", "DET0300"],
    ),
    rule(
        "execution.fileless_exec",
        1,
        T::High,
        C::Execution,
        &["T1620", "DET0300"],
    ),
    rule(
        "process.memfd",
        2,
        T::Low,
        C::Execution,
        &["T1620", "DET0300"],
    ),
    rule(
        "execution.memfd_elf",
        1,
        T::Medium,
        C::Execution,
        &["T1620"],
    ),
    rule(
        "execution.dropped_library",
        1,
        T::Medium,
        C::Execution,
        &["T1129", "DET0018"],
    ),
    // Injection
    rule("process.ptrace", 2, T::Low, C::Injection, &["T1055.008"]),
    rule(
        "injection.ptrace_attach",
        1,
        T::High,
        C::Injection,
        &["T1055.008", "DET0203"],
    ),
    rule(
        "injection.ptrace_poke",
        1,
        T::High,
        C::Injection,
        &["T1055.008", "DET0203"],
    ),
    rule(
        "injection.vm_write",
        1,
        T::High,
        C::Injection,
        &["T1055", "DET0508", "DET0203"],
    ),
    rule(
        "injection.proc_mem_write",
        1,
        T::High,
        C::Injection,
        &["T1055.009", "DET0541"],
    ),
    rule(
        "injection.ld_preload_env",
        1,
        T::Medium,
        C::Injection,
        &["T1574.006", "DET0435"],
    ),
    rule(
        "injection.dropped_preload",
        1,
        T::High,
        C::Injection,
        &["T1574.006", "DET0435"],
    ),
    rule(
        "injection.ld_so_preload",
        1,
        T::High,
        C::Injection,
        &["T1574.006", "DET0435"],
    ),
    rule(
        "injection.ld_so_conf",
        1,
        T::Medium,
        C::Injection,
        &["T1574.006"],
    )
    .allow(LINKER),
    // Persistence
    rule(
        "persistence.cron",
        1,
        T::High,
        C::Persistence,
        &["T1053.003", "DET0290"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.at_job",
        1,
        T::Medium,
        C::Persistence,
        &["T1053.002", "DET0333"],
    ),
    rule(
        "persistence.systemd",
        1,
        T::High,
        C::Persistence,
        &["T1543.002", "DET0253", "T1053.006", "DET0231"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.rc_init",
        1,
        T::High,
        C::Persistence,
        &["T1037.004", "DET0237"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.event_script",
        1,
        T::Medium,
        C::Persistence,
        &["T1037", "DET0112"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.shell_profile",
        1,
        T::Medium,
        C::Persistence,
        &["T1546.004", "DET0020"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.ssh_authorized_keys",
        1,
        T::High,
        C::Persistence,
        &["T1098.004", "DET0126"],
    )
    .allow(SSH_TOOLS),
    rule(
        "persistence.xdg_autostart",
        1,
        T::Medium,
        C::Persistence,
        &["T1547.013", "DET0390"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.udev",
        1,
        T::High,
        C::Persistence,
        &["T1546.017", "DET0375"],
    )
    .allow(PACKAGERS),
    rule("persistence.copy_running", 1, T::High, C::Persistence, &[]),
    rule(
        "persistence.pam",
        1,
        T::High,
        C::Persistence,
        &["T1556.003", "DET0454"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.module",
        1,
        T::High,
        C::Persistence,
        &["T1547.006", "DET0450"],
    ),
    rule(
        "persistence.module_autoload",
        1,
        T::High,
        C::Persistence,
        &["T1547.006", "DET0450"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.apt_hook",
        1,
        T::Medium,
        C::Persistence,
        &["T1546.016", "DET0330"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.web_shell",
        1,
        T::Medium,
        C::Persistence,
        &["T1505.003", "DET0394"],
    ),
    rule(
        "persistence.binary_replace",
        2,
        T::High,
        C::Persistence,
        &["T1554", "DET0336"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.system_dir_add",
        1,
        T::Medium,
        C::Persistence,
        &["T1036.005", "DET0347"],
    )
    .allow(PACKAGERS),
    rule(
        "persistence.account",
        1,
        T::High,
        C::Persistence,
        &["T1136.001", "DET0447", "T1098", "DET0096"],
    )
    .allow(AUTH),
    rule(
        "persistence.config_write",
        2,
        T::Low,
        C::Persistence,
        &["TA0003"],
    )
    .allow(PACKAGERS),
    // Privilege escalation
    rule("privilege.drop", 1, T::Info, C::Privilege, &["T1548"]),
    rule(
        "privilege.gain",
        1,
        T::Medium,
        C::Privilege,
        &["T1548.001", "DET0110"],
    ),
    rule(
        "privilege.setuid_exec",
        1,
        T::Low,
        C::Privilege,
        &["T1548.001"],
    ),
    rule(
        "privilege.setid_bit",
        1,
        T::High,
        C::Privilege,
        &["T1548.001", "DET0110"],
    )
    .allow(PACKAGERS),
    rule(
        "privilege.pwnkit",
        1,
        T::High,
        C::Privilege,
        &["T1068", "DET0514"],
    ),
    rule(
        "privilege.kernel_exploit",
        1,
        T::High,
        C::Privilege,
        &["T1068", "DET0514"],
    )
    .signal(),
    rule(
        "privilege.sudoers",
        1,
        T::High,
        C::Privilege,
        &["T1548.003", "DET0052"],
    )
    .allow(AUTH),
    rule("privilege.userns", 1, T::Medium, C::Privilege, &["T1068"]),
    rule(
        "privilege.kernel_helper_hijack",
        1,
        T::High,
        C::Privilege,
        &["T1611", "DET0219"],
    ),
    rule(
        "privilege.container_escape",
        1,
        T::Medium,
        C::Privilege,
        &["T1611", "DET0219", "T1610"],
    ),
    rule("privilege.dirty_pipe", 1, T::High, C::Privilege, &["T1068"]),
];

const COUNT: usize = EARLY.len() + evasion::EVASION.len() + behaviour::BEHAVIOUR.len();

/// Every rule, in the order of `EARLY`, `evasion::EVASION`, `behaviour::BEHAVIOUR`.
const ALL: [Spec; COUNT] = {
    let mut out = [rule("", 0, T::Info, C::Execution, &[]); COUNT];
    let mut at = 0;
    let parts = [EARLY, evasion::EVASION, behaviour::BEHAVIOUR];
    let mut part = 0;
    while part < parts.len() {
        let mut i = 0;
        while i < parts[part].len() {
            out[at] = parts[part][i];
            at += 1;
            i += 1;
        }
        part += 1;
    }
    out
};

pub const SPECS: &[Spec] = &ALL;
