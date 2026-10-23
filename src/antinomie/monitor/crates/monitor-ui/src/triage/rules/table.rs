// SPDX-License-Identifier: GPL-3.0-only
//! The classification: one entry per rule id, with its tier, category and
//! ATT&CK ids. Ids were checked against ATT&CK v20 (a `DET` id is a detection
//! strategy). A technique that ATT&CK lists under two tactics appears once.
use super::{Category as C, Tier as T};

pub(in crate::triage) struct Spec {
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

const fn rule(
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
    const fn signal(mut self) -> Self {
        self.signal = true;
        self
    }

    const fn allow(mut self, allow: &'static [&'static str]) -> Self {
        self.allow = allow;
        self
    }

    /// The `Source` column: where the classification comes from.
    pub(in crate::triage) fn source(&self, attack: &[&str]) -> String {
        if attack.is_empty() {
            "Observed behaviour; no ATT&CK technique".into()
        } else {
            format!("MITRE ATT&CK {}", attack.join(" · "))
        }
    }
}

pub(in crate::triage) fn spec(id: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.id == id)
}

/// Package managers and archive tools, which set times and replace system files on purpose.
const PACKAGERS: &[&str] = &[
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
const AUTH: &[&str] = &[
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
const SSH_TOOLS: &[&str] = &[
    "ssh",
    "ssh-agent",
    "ssh-add",
    "sshd",
    "sshd-session",
    "scp",
    "sftp",
];
const JIT: &[&str] = &[
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
const SERVICES: &[&str] = &[
    "systemd",
    "dbus-daemon",
    "dbus-broker-launch",
    "systemd-logind",
];

pub(in crate::triage) const SPECS: &[Spec] = &[
    // Execution
    rule("process.exec", 2, T::Info, C::Execution, &[]),
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
    ),
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
        1,
        T::High,
        C::Persistence,
        &["T1554", "DET0336"],
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
    // Defense evasion / anti-analysis
    rule("memory.rwx", 2, T::High, C::Evasion, &["T1620", "DET0300"]).allow(JIT),
    rule(
        "memory.rwx_attempt",
        2,
        T::Medium,
        C::Evasion,
        &["T1620", "DET0300"],
    )
    .signal()
    .allow(JIT),
    rule(
        "memory.wx_transition",
        1,
        T::Medium,
        C::Evasion,
        &["T1027.002", "DET0023", "T1620"],
    )
    .allow(JIT),
    rule(
        "evasion.self_delete",
        1,
        T::High,
        C::Evasion,
        &["T1070.004", "DET0140"],
    ),
    rule(
        "evasion.log_clear",
        1,
        T::High,
        C::Evasion,
        &["T1685.006", "DET0520"],
    )
    .allow(&["logrotate", "journald", "systemd-journald", "rsyslogd"]),
    rule(
        "evasion.history_clear",
        1,
        T::Medium,
        C::Evasion,
        &["T1070.003", "DET0165"],
    ),
    rule(
        "evasion.security_disable",
        1,
        T::High,
        C::Evasion,
        &["T1685", "DET0497"],
    ),
    rule(
        "evasion.firewall_modify",
        1,
        T::Medium,
        C::Evasion,
        &["T1686", "DET0145"],
    ),
    rule(
        "evasion.audit_disable",
        1,
        T::High,
        C::Evasion,
        &["T1685.004", "DET0062"],
    ),
    rule(
        "evasion.masquerade_kthread",
        1,
        T::High,
        C::Evasion,
        &["T1036.005", "DET0347", "T1036.011", "DET0164"],
    ),
    rule(
        "evasion.masquerade_daemon",
        1,
        T::Medium,
        C::Evasion,
        &["T1036.005", "T1036.011"],
    ),
    rule(
        "evasion.sandbox_probe",
        1,
        T::Medium,
        C::Evasion,
        &["T1497.001", "DET0168"],
    ),
    rule(
        "evasion.probe_then_exit",
        1,
        T::Medium,
        C::Evasion,
        &["T1497.001"],
    ),
    rule(
        "evasion.traceme",
        1,
        T::Medium,
        C::Evasion,
        &["T1622", "DET0371"],
    ),
    rule(
        "evasion.debugger_check",
        1,
        T::Low,
        C::Evasion,
        &["T1622", "DET0371"],
    ),
    rule(
        "evasion.container_check",
        1,
        T::Low,
        C::Evasion,
        &["T1497.001", "T1082"],
    ),
    rule(
        "evasion.long_sleep",
        1,
        T::Medium,
        C::Evasion,
        &["T1497.003", "DET0141"],
    ),
    rule(
        "evasion.timestomp",
        1,
        T::Medium,
        C::Evasion,
        &["T1070.006", "DET0591"],
    )
    .allow(PACKAGERS),
    rule(
        "evasion.kill_list",
        1,
        T::Medium,
        C::Evasion,
        &["T1489", "DET0021", "T1685"],
    ),
    rule(
        "evasion.hidden_artifact",
        1,
        T::Low,
        C::Evasion,
        &["T1564.001", "DET0032"],
    ),
    rule(
        "evasion.immutable_attr",
        1,
        T::High,
        C::Evasion,
        &["T1222.002", "DET0351"],
    ),
    rule(
        "evasion.proc_hide_mount",
        1,
        T::High,
        C::Evasion,
        &["T1564.013", "DET0428"],
    ),
    rule(
        "evasion.sysctl_security",
        1,
        T::Medium,
        C::Evasion,
        &["T1685", "DET0497"],
    ),
    rule("evasion.dumpable_off", 1, T::Low, C::Evasion, &["T1622"]),
    rule("evasion.io_uring_usage", 1, T::Info, C::Evasion, &[]),
    rule("bpf.seccomp_filter", 2, T::Low, C::Evasion, &[]).allow(SERVICES),
    // Credential access
    rule(
        "credential.shadow_read",
        1,
        T::High,
        C::Credential,
        &["T1003.008", "DET0446"],
    )
    .allow(AUTH),
    rule(
        "credential.ssh_keys",
        1,
        T::Medium,
        C::Credential,
        &["T1552.004", "DET0549"],
    )
    .allow(SSH_TOOLS),
    rule(
        "credential.cloud_tokens",
        1,
        T::High,
        C::Credential,
        &["T1552.001", "DET0307"],
    )
    .allow(&["aws", "gcloud", "az", "kubectl", "docker", "git", "curl"]),
    rule(
        "credential.browser_store",
        1,
        T::Medium,
        C::Credential,
        &["T1555.003", "DET0037"],
    )
    .allow(&[
        "firefox",
        "firefox-esr",
        "chrome",
        "chromium",
        "brave",
        "msedge",
    ]),
    rule(
        "credential.wallet",
        1,
        T::Medium,
        C::Credential,
        &["T1657", "DET0495", "T1005", "DET0380"],
    ),
    rule(
        "credential.history_read",
        1,
        T::Low,
        C::Credential,
        &["T1552.003", "DET0385"],
    )
    .allow(&[
        "bash", "zsh", "sh", "dash", "fish", "mysql", "psql", "python3",
    ]),
    rule(
        "credential.kerberos_ccache",
        1,
        T::Medium,
        C::Credential,
        &["T1558.005", "DET0024"],
    )
    .allow(&["klist", "kinit", "kdestroy", "sssd", "sssd_be", "sshd"]),
    rule(
        "credential.proc_mem_read",
        1,
        T::High,
        C::Credential,
        &["T1003.007", "DET0593"],
    ),
    rule(
        "credential.cloud_metadata",
        1,
        T::High,
        C::Credential,
        &["T1552.005", "DET0001"],
    ),
    // Discovery
    rule(
        "discovery.process_enum",
        1,
        T::Low,
        C::Discovery,
        &["T1057", "DET0034"],
    ),
    rule(
        "discovery.system_info",
        1,
        T::Info,
        C::Discovery,
        &["T1082", "DET0525"],
    ),
    rule(
        "discovery.network_config",
        1,
        T::Low,
        C::Discovery,
        &["T1016", "DET0195", "T1049", "DET0320"],
    ),
    rule(
        "discovery.user_enum",
        1,
        T::Info,
        C::Discovery,
        &["T1033", "DET0093", "T1087.001", "DET0303"],
    ),
    rule(
        "discovery.file_search",
        1,
        T::Low,
        C::Discovery,
        &["T1083", "DET0370"],
    ),
    rule(
        "discovery.security_software",
        1,
        T::Medium,
        C::Discovery,
        &["T1518.001", "DET0016"],
    ),
    rule(
        "discovery.network_scan",
        1,
        T::Medium,
        C::Discovery,
        &["T1046", "DET0376"],
    )
    .signal(),
    // Command and control
    rule(
        "c2.reverse_shell",
        1,
        T::High,
        C::Command,
        &["T1059.004", "DET0384", "T1095"],
    ),
    rule("c2.bind_shell", 1, T::High, C::Command, &["T1059.004"]),
    rule("network.listen_any", 1, T::Medium, C::Command, &[]),
    rule(
        "network.raw_socket",
        1,
        T::Medium,
        C::Command,
        &["T1095", "DET0457", "T1040", "DET0314"],
    ),
    rule(
        "c2.bpf_backdoor",
        1,
        T::High,
        C::Command,
        &["T1205.002", "DET0162"],
    ),
    rule(
        "bpf.socket_filter",
        1,
        T::Medium,
        C::Command,
        &["T1205.002", "DET0162"],
    ),
    rule(
        "network.tor",
        1,
        T::Medium,
        C::Command,
        &["T1090.003", "DET0359"],
    ),
    rule(
        "network.ip_literal",
        1,
        T::Low,
        C::Command,
        &["T1071.001", "DET0027"],
    ),
    rule(
        "network.dga_nxdomain",
        1,
        T::Medium,
        C::Command,
        &["T1568.002", "DET0419"],
    ),
    rule(
        "network.dns_tunnel",
        1,
        T::Medium,
        C::Command,
        &["T1071.004", "DET0400"],
    ),
    rule(
        "network.nonstandard_port",
        1,
        T::Low,
        C::Command,
        &["T1571", "DET0227"],
    ),
    rule(
        "network.irc_c2",
        1,
        T::Medium,
        C::Command,
        &["T1071", "DET0444"],
    ),
    rule(
        "network.web_service",
        1,
        T::Low,
        C::Command,
        &[
            "T1102",
            "DET0425",
            "T1102.002",
            "DET0035",
            "T1567",
            "DET0548",
        ],
    ),
    rule(
        "network.beacon",
        1,
        T::Low,
        C::Command,
        &["T1071", "DET0444"],
    ),
    rule(
        "network.proxy_tunnel",
        1,
        T::Medium,
        C::Command,
        &["T1572", "DET0538", "T1090", "DET0445"],
    ),
    rule(
        "c2.elf_download",
        1,
        T::High,
        C::Command,
        &["T1105", "DET0060"],
    ),
    // Lateral movement
    rule(
        "lateral.ssh_spread",
        1,
        T::High,
        C::Lateral,
        &["T1021.004", "DET0596", "T1552.004", "DET0549"],
    ),
    rule(
        "lateral.bruteforce",
        1,
        T::High,
        C::Lateral,
        &["T1110.001", "DET0551"],
    )
    .signal(),
    rule(
        "lateral.service_exploit",
        1,
        T::Medium,
        C::Lateral,
        &["T1210", "DET0118", "T1133", "DET0354"],
    )
    .signal(),
    rule(
        "lateral.tool_transfer",
        1,
        T::Medium,
        C::Lateral,
        &["T1570", "DET0183"],
    ),
    // Exfiltration
    rule(
        "exfil.file_to_socket",
        1,
        T::Medium,
        C::Exfiltration,
        &["T1041", "DET0348", "T1048", "DET0131"],
    ),
    rule(
        "exfil.large_upload",
        1,
        T::Medium,
        C::Exfiltration,
        &["T1041", "T1048"],
    ),
    // Collection
    rule(
        "collection.keylog",
        1,
        T::Medium,
        C::Collection,
        &["T1056.001", "DET0089"],
    ),
    rule("collection.tty_inject", 1, T::Medium, C::Collection, &[]),
    rule(
        "collection.screen_capture",
        1,
        T::Low,
        C::Collection,
        &["T1113", "DET0346"],
    ),
    rule(
        "collection.av_capture",
        1,
        T::Low,
        C::Collection,
        &["T1123", "DET0221", "T1125", "DET0197"],
    ),
    rule(
        "collection.archive_staging",
        1,
        T::Medium,
        C::Collection,
        &["T1560.001", "DET0298", "T1074.001", "DET0261"],
    ),
    rule(
        "collection.clipboard",
        1,
        T::Low,
        C::Collection,
        &["T1115", "DET0341"],
    ),
    rule(
        "collection.local_sweep",
        1,
        T::Low,
        C::Collection,
        &["T1005", "DET0380"],
    ),
    // Impact
    rule(
        "impact.ransom_rewrite",
        1,
        T::High,
        C::Impact,
        &["T1486", "DET0215"],
    ),
    rule("impact.ransom_note", 1, T::Medium, C::Impact, &["T1486"]),
    rule(
        "impact.mass_delete",
        1,
        T::High,
        C::Impact,
        &["T1485", "DET0146"],
    ),
    rule(
        "impact.block_device_write",
        1,
        T::High,
        C::Impact,
        &["T1561.001", "DET0316", "T1561.002", "DET0297"],
    ),
    rule(
        "impact.reboot",
        1,
        T::High,
        C::Impact,
        &["T1529", "DET0559"],
    ),
    rule(
        "impact.miner",
        1,
        T::High,
        C::Impact,
        &["T1496.001", "DET0540"],
    ),
    rule(
        "impact.miner_tuning",
        1,
        T::Medium,
        C::Impact,
        &["T1496.001"],
    ),
    rule(
        "impact.fork_bomb",
        1,
        T::Medium,
        C::Impact,
        &["T1499.001", "DET0356"],
    )
    .signal(),
    rule(
        "impact.ddos_flood",
        1,
        T::High,
        C::Impact,
        &["T1498.001", "DET0343"],
    ),
    rule(
        "impact.service_stop",
        1,
        T::Medium,
        C::Impact,
        &["T1489", "DET0021"],
    ),
    rule(
        "impact.inhibit_recovery",
        1,
        T::Medium,
        C::Impact,
        &["T1490", "DET0329"],
    ),
    // Rootkit
    rule(
        "bpf.program",
        1,
        T::Medium,
        C::Rootkit,
        &["T1014", "DET0377"],
    ),
    rule(
        "rootkit.dev_mem",
        1,
        T::High,
        C::Rootkit,
        &["T1014", "DET0377"],
    ),
];
