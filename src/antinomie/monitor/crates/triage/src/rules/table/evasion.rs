// SPDX-License-Identifier: GPL-3.0-only
//! The classification of defense evasion and anti-analysis rules.
use super::{rule, Spec, JIT, PACKAGERS, SERVICES};
use crate::rules::{Category as C, Tier as T};

pub const EVASION: &[Spec] = &[
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
        "evasion.tool_delete",
        1,
        T::Medium,
        C::Evasion,
        &["T1070.004", "DET0140"],
    )
    .allow(PACKAGERS),
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
        2,
        T::Medium,
        C::Evasion,
        &["T1686", "DET0145"],
    ),
    rule(
        "evasion.watchdog_disable",
        2,
        T::High,
        C::Evasion,
        &["T1490", "DET0329"],
    )
    .allow(&["watchdog", "wd_keepalive", "systemd", "wdctl"]),
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
        "evasion.argv_masquerade",
        1,
        T::Low,
        C::Evasion,
        &["T1036.005"],
    ),
    rule(
        "evasion.process_rename",
        1,
        T::Low,
        C::Evasion,
        &["T1036.005"],
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
        "evasion.packed_image",
        1,
        T::Medium,
        C::Evasion,
        &["T1027.002"],
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
        "evasion.process_killer",
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
];
