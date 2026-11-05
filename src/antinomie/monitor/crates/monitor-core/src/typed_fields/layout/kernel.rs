// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Names for the kernel-interface structures whose members need more than the
//! generic rules: `perf_event_attr` (the event by type and config, the
//! one-bit options gathered as flags), the SysV IPC, disk-quota and LSM
//! structures (times as dates, the flag words by name).
type Table = &'static [(&'static str, u64)];
use crate::typed_fields::{Node, c_string};

pub(super) const SAMPLE_TYPE: Table = &[
    ("PERF_SAMPLE_IP", 1 << 0),
    ("PERF_SAMPLE_TID", 1 << 1),
    ("PERF_SAMPLE_TIME", 1 << 2),
    ("PERF_SAMPLE_ADDR", 1 << 3),
    ("PERF_SAMPLE_READ", 1 << 4),
    ("PERF_SAMPLE_CALLCHAIN", 1 << 5),
    ("PERF_SAMPLE_ID", 1 << 6),
    ("PERF_SAMPLE_CPU", 1 << 7),
    ("PERF_SAMPLE_PERIOD", 1 << 8),
    ("PERF_SAMPLE_STREAM_ID", 1 << 9),
    ("PERF_SAMPLE_RAW", 1 << 10),
    ("PERF_SAMPLE_BRANCH_STACK", 1 << 11),
    ("PERF_SAMPLE_REGS_USER", 1 << 12),
    ("PERF_SAMPLE_STACK_USER", 1 << 13),
    ("PERF_SAMPLE_WEIGHT", 1 << 14),
    ("PERF_SAMPLE_DATA_SRC", 1 << 15),
    ("PERF_SAMPLE_IDENTIFIER", 1 << 16),
    ("PERF_SAMPLE_TRANSACTION", 1 << 17),
    ("PERF_SAMPLE_REGS_INTR", 1 << 18),
    ("PERF_SAMPLE_PHYS_ADDR", 1 << 19),
    ("PERF_SAMPLE_AUX", 1 << 20),
    ("PERF_SAMPLE_CGROUP", 1 << 21),
    ("PERF_SAMPLE_DATA_PAGE_SIZE", 1 << 22),
    ("PERF_SAMPLE_CODE_PAGE_SIZE", 1 << 23),
    ("PERF_SAMPLE_WEIGHT_STRUCT", 1 << 24),
];

pub(super) const READ_FORMAT: Table = &[
    ("PERF_FORMAT_TOTAL_TIME_ENABLED", 1 << 0),
    ("PERF_FORMAT_TOTAL_TIME_RUNNING", 1 << 1),
    ("PERF_FORMAT_ID", 1 << 2),
    ("PERF_FORMAT_GROUP", 1 << 3),
    ("PERF_FORMAT_LOST", 1 << 4),
];

pub(super) const PRECISE_IP: Table = &[
    ("arbitrary skid", 0),
    ("constant skid", 1),
    ("requested zero skid", 2),
    ("zero skid", 3),
];

pub(super) const BREAKPOINT_TYPE: Table = &[
    ("HW_BREAKPOINT_EMPTY", 0),
    ("HW_BREAKPOINT_R", 1),
    ("HW_BREAKPOINT_W", 2),
    ("HW_BREAKPOINT_RW", 3),
    ("HW_BREAKPOINT_X", 4),
];

const HARDWARE: &[&str] = &[
    "CPU_CYCLES",
    "INSTRUCTIONS",
    "CACHE_REFERENCES",
    "CACHE_MISSES",
    "BRANCH_INSTRUCTIONS",
    "BRANCH_MISSES",
    "BUS_CYCLES",
    "STALLED_CYCLES_FRONTEND",
    "STALLED_CYCLES_BACKEND",
    "REF_CPU_CYCLES",
];

const SOFTWARE: &[&str] = &[
    "CPU_CLOCK",
    "TASK_CLOCK",
    "PAGE_FAULTS",
    "CONTEXT_SWITCHES",
    "CPU_MIGRATIONS",
    "PAGE_FAULTS_MIN",
    "PAGE_FAULTS_MAJ",
    "ALIGNMENT_FAULTS",
    "EMULATION_FAULTS",
    "DUMMY",
    "BPF_OUTPUT",
    "CGROUP_SWITCHES",
];

const CACHES: &[&str] = &["L1D", "L1I", "LL", "DTLB", "ITLB", "BPU", "NODE"];
const CACHE_OPS: &[&str] = &["READ", "WRITE", "PREFETCH"];
const CACHE_RESULTS: &[&str] = &["ACCESS", "MISS"];

/// The one-bit members of `perf_event_attr`, gathered as `flags`.
const PERF_BITS: &[&str] = &[
    "disabled",
    "inherit",
    "pinned",
    "exclusive",
    "exclude_user",
    "exclude_kernel",
    "exclude_hv",
    "exclude_idle",
    "mmap",
    "comm",
    "freq",
    "inherit_stat",
    "enable_on_exec",
    "task",
    "watermark",
    "mmap_data",
    "sample_id_all",
    "exclude_host",
    "exclude_guest",
    "exclude_callchain_kernel",
    "exclude_callchain_user",
    "mmap2",
    "comm_exec",
    "use_clockid",
    "context_switch",
    "write_backward",
    "namespaces",
    "ksymbol",
    "bpf_event",
    "aux_output",
    "cgroup",
    "text_poke",
    "build_id",
    "inherit_thread",
    "remove_on_exec",
    "sigtrap",
];

pub(super) const QIF: Table = &[
    ("QIF_BLIMITS", 1),
    ("QIF_SPACE", 2),
    ("QIF_ILIMITS", 4),
    ("QIF_INODES", 8),
    ("QIF_BTIME", 16),
    ("QIF_ITIME", 32),
];

pub(super) const DQF: Table = &[("DQF_ROOT_SQUASH", 1), ("DQF_SYS_FILE", 0x1_0000)];

pub(super) const IIF: Table = &[("IIF_BGRACE", 1), ("IIF_IGRACE", 2), ("IIF_FLAGS", 4)];

pub(super) const FS_QUOTA_STATE: Table = &[
    ("FS_QUOTA_UDQ_ACCT", 0x01),
    ("FS_QUOTA_UDQ_ENFD", 0x02),
    ("FS_QUOTA_GDQ_ACCT", 0x04),
    ("FS_QUOTA_GDQ_ENFD", 0x08),
    ("FS_QUOTA_PDQ_ACCT", 0x10),
    ("FS_QUOTA_PDQ_ENFD", 0x20),
];

pub(super) const FS_QUOTA_TYPE: Table = &[
    ("FS_USER_QUOTA", 1),
    ("FS_PROJ_QUOTA", 2),
    ("FS_GROUP_QUOTA", 4),
];

pub(super) const FS_DQ_FIELDS: Table = &[
    ("FS_DQ_ISOFT", 0x1),
    ("FS_DQ_IHARD", 0x2),
    ("FS_DQ_BSOFT", 0x4),
    ("FS_DQ_BHARD", 0x8),
    ("FS_DQ_RTBSOFT", 0x10),
    ("FS_DQ_RTBHARD", 0x20),
    ("FS_DQ_BTIMER", 0x40),
    ("FS_DQ_ITIMER", 0x80),
    ("FS_DQ_RTBTIMER", 0x100),
    ("FS_DQ_BWARNS", 0x200),
    ("FS_DQ_IWARNS", 0x400),
    ("FS_DQ_RTBWARNS", 0x800),
    ("FS_DQ_BCOUNT", 0x1000),
    ("FS_DQ_ICOUNT", 0x2000),
    ("FS_DQ_RTBCOUNT", 0x4000),
];

pub(crate) const LSM_ID: Table = &[
    ("LSM_ID_UNDEF", 0),
    ("LSM_ID_CAPABILITY", 100),
    ("LSM_ID_SELINUX", 101),
    ("LSM_ID_SMACK", 102),
    ("LSM_ID_TOMOYO", 103),
    ("LSM_ID_APPARMOR", 104),
    ("LSM_ID_YAMA", 105),
    ("LSM_ID_LOADPIN", 106),
    ("LSM_ID_SAFESETID", 107),
    ("LSM_ID_LOCKDOWN", 108),
    ("LSM_ID_BPF", 109),
    ("LSM_ID_LANDLOCK", 110),
    ("LSM_ID_IMA", 111),
    ("LSM_ID_EVM", 112),
    ("LSM_ID_IPE", 113),
];

pub(crate) const LSM_ATTR: Table = &[
    ("LSM_ATTR_CURRENT", 100),
    ("LSM_ATTR_EXEC", 101),
    ("LSM_ATTR_FSCREATE", 102),
    ("LSM_ATTR_KEYCREATE", 103),
    ("LSM_ATTR_PREV", 104),
    ("LSM_ATTR_SOCKCREATE", 105),
];

pub(crate) const LSM_FLAGS: Table = &[("LSM_FLAG_SINGLE", 1)];

fn word(data: &[u8], at: usize, width: usize) -> Option<u64> {
    crate::typed_fields::spec::word(data, at, width)
}

/// A perf event's config by its type: the hardware event, software event or
/// cache event by name; a tracepoint by id; anything else in hex.
fn perf_config(kind: u64, config: u64) -> String {
    let list = |names: &[&str], prefix: &str| {
        usize::try_from(config)
            .ok()
            .and_then(|index| names.get(index))
            .map(|name| format!("{prefix}{name}"))
    };
    let text = match kind {
        0 => list(HARDWARE, "PERF_COUNT_HW_"),
        1 => list(SOFTWARE, "PERF_COUNT_SW_"),
        2 => Some(format!("tracepoint {config}")),
        3 => {
            let part = |names: &'static [&'static str], shift: u32| {
                names
                    .get(usize::try_from(config >> shift & 0xff).unwrap_or(usize::MAX))
                    .copied()
            };
            match (part(CACHES, 0), part(CACHE_OPS, 8), part(CACHE_RESULTS, 16)) {
                (Some(cache), Some(op), Some(result)) => Some(format!(
                    "PERF_COUNT_HW_CACHE_{cache}|OP_{op}|RESULT_{result}"
                )),
                _ => None,
            }
        }
        _ => None,
    };
    text.unwrap_or_else(|| format!("{config:#x}"))
}

/// Rewrites the decoded members of the layouts that need it, from the
/// layout's own bytes.
pub(super) fn refine(layout: &str, nodes: &mut Vec<Node>, data: &[u8]) {
    match layout {
        "perf_event_attr" => {
            if let (Some(kind), Some(config)) = (word(data, 0, 4), word(data, 8, 8))
                && let Some(node) = nodes.iter_mut().find(|node| node.name == "config")
            {
                node.text = perf_config(kind, config);
            }
            let first = nodes
                .iter()
                .position(|node| PERF_BITS.contains(&node.name.as_str()));
            let set: Vec<String> = nodes
                .iter()
                .filter(|node| PERF_BITS.contains(&node.name.as_str()))
                .map(|node| node.name.clone())
                .collect();
            if let Some(first) = first {
                nodes.retain(|node| !PERF_BITS.contains(&node.name.as_str()));
                nodes.insert(first, Node::leaf("flags", set.join("|")));
            }
        }
        "lsm_ctx" => {
            let length = word(data, 24, 8).and_then(|len| usize::try_from(len).ok());
            if let Some(length) = length
                && let Some(bytes) = data.get(32..)
                && !bytes.is_empty()
            {
                nodes.push(Node::leaf(
                    "ctx",
                    c_string(&bytes[..bytes.len().min(length)]),
                ));
            }
        }
        _ => {}
    }
}
