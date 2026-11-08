// SPDX-License-Identifier: GPL-3.0-only
//! Looking at, and ending, the QEMU process a dead service left (design
//! 4.7.3): a recorded pid is killed only when `/proc/<pid>/cmdline` shows it
//! is still that VM's QEMU. [`Processes`] is the seam; [`ProcFs`] is the real
//! one and tests use a table.
use super::state::QemuRecord;
use std::{fs, thread, time::Duration};

/// What `/proc` says about one process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub argv: Vec<String>,
    /// Field 22 of `/proc/<pid>/stat`.
    pub start_ticks: Option<u64>,
}

pub trait Processes {
    /// The process with this pid, or `None` when there is none.
    fn info(&self, pid: u32) -> Option<ProcessInfo>;
    /// End the process and wait a short while for it to go. Err names why it
    /// stays.
    fn kill(&self, pid: u32) -> Result<(), String>;
}

/// Whether `info` is the QEMU of the recorded VM.
pub fn is_recorded_qemu(record: &QemuRecord, info: &ProcessInfo) -> bool {
    let program = info
        .argv
        .first()
        .and_then(|arg0| arg0.rsplit('/').next())
        .unwrap_or("");
    program.starts_with("qemu-system")
        && !record.marker.is_empty()
        && info.argv.iter().any(|arg| arg.contains(&record.marker))
        && match (record.start_ticks, info.start_ticks) {
            (Some(recorded), Some(now)) => recorded == now,
            // A pid recorded without ticks is checked by its command line only.
            (None, _) => true,
            (Some(_), None) => false,
        }
}

/// The real `/proc`.
pub struct ProcFs;

fn start_ticks(stat: &str) -> Option<u64> {
    // The name may contain spaces and parentheses; the fields after the last
    // `)` are state (3) onward, so field 22 is the 20th after it.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

impl Processes for ProcFs {
    fn info(&self, pid: u32) -> Option<ProcessInfo> {
        let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let argv = raw
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        let ticks = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| start_ticks(&stat));
        Some(ProcessInfo {
            argv,
            start_ticks: ticks,
        })
    }

    fn kill(&self, pid: u32) -> Result<(), String> {
        let target = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| format!("{pid} is not a process id"))?;
        rustix::process::kill_process(target, rustix::process::Signal::KILL)
            .map_err(|e| format!("could not kill {pid}: {e}"))?;
        for _ in 0..50 {
            // A killed child of another process stays a zombie until it is
            // reaped; its command line is then empty, which `info` reports as
            // no argv.
            match self.info(pid) {
                None => return Ok(()),
                Some(info) if info.argv.is_empty() => return Ok(()),
                Some(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        Err(format!(
            "process {pid} is still there 5 seconds after SIGKILL"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_time_is_found_after_a_name_with_spaces_and_parentheses() {
        let stat =
            "123 (qemu (x) y) S 1 123 123 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 3 0 987654 1 2";
        assert_eq!(start_ticks(stat), Some(987654));
        assert_eq!(start_ticks("garbage"), None);
    }

    fn record(ticks: Option<u64>) -> QemuRecord {
        QemuRecord {
            pid: 5,
            start_ticks: ticks,
            marker: "auto-1".into(),
            recorded_ms: 0,
        }
    }

    fn info(argv: &[&str], ticks: Option<u64>) -> ProcessInfo {
        ProcessInfo {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            start_ticks: ticks,
        }
    }

    #[test]
    fn only_the_recorded_vms_qemu_matches() {
        let qemu = info(
            &[
                "/usr/bin/qemu-system-x86_64",
                "-drive",
                "file=/d/vms/auto-1/disk.qcow2",
            ],
            Some(10),
        );
        assert!(is_recorded_qemu(&record(Some(10)), &qemu));
        assert!(is_recorded_qemu(&record(None), &qemu));
        assert!(!is_recorded_qemu(&record(Some(11)), &qemu), "a reused pid");
        let other_vm = info(&["qemu-system-x86_64", "file=/d/vms/other/disk"], Some(10));
        assert!(!is_recorded_qemu(&record(Some(10)), &other_vm));
        let not_qemu = info(&["/bin/sleep", "auto-1"], Some(10));
        assert!(!is_recorded_qemu(&record(Some(10)), &not_qemu));
        let mut empty = record(None);
        empty.marker.clear();
        assert!(
            !is_recorded_qemu(&empty, &qemu),
            "an empty marker matches nothing"
        );
    }

    #[test]
    fn our_own_process_is_found_and_a_missing_one_is_not() {
        let me = ProcFs.info(std::process::id()).unwrap();
        assert!(!me.argv.is_empty());
        assert!(me.start_ticks.is_some());
        assert!(ProcFs.info(u32::MAX - 1).is_none());
    }
}
