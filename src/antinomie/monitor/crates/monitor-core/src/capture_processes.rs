//! The processes a capture observed, as a tree: Capture All splits its
//! events by process the way launched programs are split into runs.
//!
//! The tree comes from the guest process list read when the capture starts
//! and from the capture's own lifecycle events: a fork names the child's
//! thread group, an exec commit renames the process after the path of its
//! execve, and a thread group's exit ends it.
use crate::{api::EventSummary, observation::GuestProcess, parser::Header};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureProcess {
    /// Thread group ID in the guest.
    pub pid: u32,
    /// Parent thread group; 0 when unknown (a process seen only by its packets).
    pub parent_pid: u32,
    /// Command name, or the file name of the last program it executed.
    pub name: String,
    /// Path of the last program it executed during the capture.
    pub exe: Option<String>,
    /// Running when the capture started (from the guest process list).
    pub at_start: bool,
    /// Guest time of its first and last observed packet.
    pub first_ns: u64,
    pub last_ns: u64,
    /// System calls observed (entry events).
    pub calls: u64,
    pub packets: u64,
    /// Its thread group exited during the capture, with this exit code.
    pub exited: bool,
    pub exit_code: Option<i64>,
}

#[derive(Default)]
pub struct ProcessTracker {
    processes: BTreeMap<u32, CaptureProcess>,
    /// Program path of the latest execve entry per thread group, applied when
    /// the exec commits.
    exec_paths: BTreeMap<u32, ExecPath>,
    /// At most one lifetime boundary per already tracked PID.
    lifetimes: BTreeMap<u32, Lifetime>,
    changed: bool,
}

#[derive(Default)]
struct Lifetime {
    born_ns: u64,
    exit_ns: u64,
    exec_ns: u64,
    leader: Option<(u64, u64)>,
    leader_ns: u64,
}

struct ExecPath {
    identity: (u64, u64),
    timestamp_ns: u64,
    path: String,
}

/// The key of an exec's program path: its `filename` argument by position in
/// the run's table, named `path` in captured fields.
fn exec_path_key(event: &EventSummary) -> Option<String> {
    if !matches!(event.syscall_name.as_str(), "execve" | "execveat") {
        return None;
    }
    let index = crate::syscalls::native().argument(&event.syscall_name, "filename")?;
    Some(format!("arg{index}.path"))
}

fn field_u64(event: &EventSummary, key: &str) -> Option<u64> {
    let field = event.fields.iter().find(|field| field.key == key)?;
    Some(u64::from_le_bytes(field.preview.get(..8)?.try_into().ok()?))
}

fn field_text(event: &EventSummary, key: &str) -> Option<String> {
    preview_text(&event.fields.iter().find(|field| field.key == key)?.preview)
}

fn preview_text(preview: &[u8]) -> Option<String> {
    let bytes = preview.split(|byte| *byte == 0).next()?;
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
}

fn file_name(path: &str) -> String {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
        .to_owned()
}

impl ProcessTracker {
    /// Restore descriptive checkpoint baselines; pending exec observations are not replayed.
    pub(crate) fn restore_baseline(&mut self, processes: Vec<CaptureProcess>) {
        self.processes = processes
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        self.exec_paths.clear();
        self.lifetimes = self
            .processes
            .iter()
            .map(|(pid, process)| {
                (
                    *pid,
                    Lifetime {
                        exit_ns: if process.exited { process.last_ns } else { 0 },
                        exec_ns: process.last_ns,
                        ..Lifetime::default()
                    },
                )
            })
            .collect();
        self.changed = true;
    }

    /// Processes running when the capture started.
    pub fn seed(&mut self, processes: &[GuestProcess]) {
        for process in processes {
            let entry = self
                .processes
                .entry(process.identity.tgid)
                .or_insert_with(|| CaptureProcess {
                    pid: process.identity.tgid,
                    ..CaptureProcess::default()
                });
            entry.at_start = true;
            if entry.parent_pid == 0 {
                entry.parent_pid = process.parent_tgid;
            }
            if entry.name.is_empty() {
                entry.name = process.command.clone();
            }
        }
        self.changed = true;
    }

    fn process(&mut self, pid: u32) -> &mut CaptureProcess {
        self.processes.entry(pid).or_insert_with(|| CaptureProcess {
            pid,
            ..CaptureProcess::default()
        })
    }

    fn before_birth(&self, pid: u32, timestamp_ns: u64) -> bool {
        timestamp_ns != 0
            && self
                .lifetimes
                .get(&pid)
                .is_some_and(|life| life.born_ns != 0 && timestamp_ns < life.born_ns)
    }

    fn reset_lifetime(&mut self, pid: u32, born_ns: u64) {
        self.processes.insert(
            pid,
            CaptureProcess {
                pid,
                ..CaptureProcess::default()
            },
        );
        self.exec_paths.remove(&pid);
        self.lifetimes.insert(
            pid,
            Lifetime {
                born_ns,
                ..Lifetime::default()
            },
        );
        self.changed = true;
    }

    /// Guest time orders CPU streams; a PID alone never proves reuse.
    fn observe_identity(
        &mut self,
        pid: u32,
        tid: u32,
        stream: u64,
        cookie: u64,
        time: u64,
    ) -> bool {
        if self.before_birth(pid, time) {
            return false;
        }
        if tid != pid || cookie == 0 {
            return true;
        }
        let identity = (stream, cookie);
        if let Some(life) = self.lifetimes.get(&pid)
            && life.leader.is_some_and(|known| known != identity)
        {
            if time == 0 || time < life.leader_ns {
                return false;
            }
            if life.exit_ns != 0 && time > life.exit_ns {
                let lower_bound = life.exit_ns.saturating_add(1);
                // A non-leader thread can exec and become the leader.
                // Its already captured path belongs to this identity.
                let pending = self.exec_paths.remove(&pid).filter(|pending| {
                    pending.identity == identity && pending.timestamp_ns >= lower_bound
                });
                self.reset_lifetime(pid, lower_bound);
                if let Some(pending) = pending {
                    self.exec_paths.insert(pid, pending);
                }
            }
        }
        let life = self.lifetimes.entry(pid).or_default();
        life.leader = Some(identity);
        life.leader_ns = life.leader_ns.max(time);
        true
    }

    /// True when `pid` has no name yet (the app launched it, so no execve or
    /// fork of it was observed).
    pub fn unnamed(&self, pid: u32) -> bool {
        self.processes.get(&pid).is_some_and(|p| p.name.is_empty())
    }

    /// Name a process after the program the app launched for it.
    pub fn name_launched(&mut self, pid: u32, path: &str) {
        let process = self.process(pid);
        if process.name.is_empty() {
            process.name = file_name(path);
            process.exe = Some(path.to_owned());
            self.changed = true;
        }
    }

    /// Count one captured packet against its process.
    pub fn packet(&mut self, header: &Header) {
        if header.pid == 0 || header.record_type != 1 {
            return;
        }
        if !self.observe_identity(
            header.pid,
            header.tid,
            header.stream_id,
            header.task_cookie,
            header.timestamp_ns,
        ) {
            return;
        }
        let process = self.process(header.pid);
        if process.first_ns == 0 || header.timestamp_ns < process.first_ns {
            process.first_ns = header.timestamp_ns;
        }
        process.last_ns = process.last_ns.max(header.timestamp_ns);
        process.packets += 1;
        if header.phase == 1 && header.fragment == 1 {
            process.calls += 1;
        }
        self.changed = true;
    }

    /// Apply an assembled event: execve paths and fork, exec and exit records.
    pub fn event(&mut self, event: &EventSummary) {
        if event.pid == 0 {
            return;
        }
        if !self.observe_identity(
            event.pid,
            event.tid,
            event.stream_id,
            event.task_cookie,
            event.timestamp_ns,
        ) {
            return;
        }
        // An exec names its program in the argument the table calls `filename`.
        if event.phase == 1 {
            if event.timestamp_ns != 0
                && self
                    .lifetimes
                    .get(&event.pid)
                    .is_some_and(|life| event.timestamp_ns < life.exec_ns)
            {
                return;
            }
            let Some(key) = exec_path_key(event) else {
                return;
            };
            let key = key.as_str();
            if let Some(path) = field_text(event, key)
                && self
                    .exec_paths
                    .get(&event.pid)
                    .is_none_or(|pending| pending.timestamp_ns <= event.timestamp_ns)
            {
                self.exec_paths.insert(
                    event.pid,
                    ExecPath {
                        identity: (event.stream_id, event.task_cookie),
                        timestamp_ns: event.timestamp_ns,
                        path,
                    },
                );
            }
            return;
        }
        // An exec whose Entry could not read the path publishes it at its
        // Exit (contract 22): the exec's own copy, after the commit record.
        if event.phase == 2 {
            let Some(key) = exec_path_key(event) else {
                return;
            };
            let key = key.as_str();
            let recaptured = event
                .fields
                .iter()
                .find(|field| field.key == key && field.recapture.is_some() && field.complete);
            if event.result == Some(0)
                && let Some(path) = recaptured.and_then(|field| preview_text(&field.preview))
                && self
                    .lifetimes
                    .get(&event.pid)
                    .is_none_or(|life| event.timestamp_ns >= life.exec_ns)
            {
                self.lifetimes.entry(event.pid).or_default().exec_ns = event.timestamp_ns;
                let process = self.process(event.pid);
                process.name = file_name(&path);
                process.exe = Some(path);
                self.changed = true;
            }
            return;
        }
        if event.phase != 3 || !event.complete {
            return;
        }
        if let Some(child) = field_u64(event, "lifecycle.child_tgid") {
            let Ok(child) = u32::try_from(child) else {
                return;
            };
            if child != 0 && child != event.pid && !self.before_birth(child, event.timestamp_ns) {
                let parent = self
                    .processes
                    .get(&event.pid)
                    .map(|parent| (parent.name.clone(), parent.exe.clone()))
                    .unwrap_or_default();
                let terminal = self.lifetimes.get(&child).map_or(0, |life| life.exit_ns);
                // Older forks can be delivered after their child's exit. Only
                // a fork strictly after the established exit proves PID reuse.
                if terminal != 0 && event.timestamp_ns > terminal {
                    self.reset_lifetime(child, event.timestamp_ns);
                }
                let life = self.lifetimes.entry(child).or_default();
                if event.timestamp_ns != 0 && life.born_ns == 0 {
                    life.born_ns = event.timestamp_ns;
                }
                let process = self.process(child);
                process.parent_pid = event.pid;
                if process.name.is_empty() {
                    (process.name, process.exe) = parent;
                }
                self.changed = true;
            }
        } else if field_u64(event, "lifecycle.exec_commit").is_some() {
            let last_exec = self
                .lifetimes
                .get(&event.pid)
                .map_or(0, |life| life.exec_ns);
            let applicable = event.timestamp_ns >= last_exec
                && self.exec_paths.get(&event.pid).is_some_and(|pending| {
                    pending.identity == (event.stream_id, event.task_cookie)
                        && pending.timestamp_ns <= event.timestamp_ns
                });
            if applicable && let Some(pending) = self.exec_paths.remove(&event.pid) {
                self.lifetimes.entry(event.pid).or_default().exec_ns = event.timestamp_ns;
                let process = self.process(event.pid);
                process.name = file_name(&pending.path);
                process.exe = Some(pending.path);
                self.changed = true;
            }
        } else if let Some(code) = field_u64(event, "lifecycle.task_exit") {
            // Only the thread group leader's exit ends the process.
            if event.tid == event.pid {
                let life = self.lifetimes.entry(event.pid).or_default();
                if life.exit_ns != 0 && event.timestamp_ns < life.exit_ns {
                    return;
                }
                life.exit_ns = event.timestamp_ns;
                let process = self.process(event.pid);
                process.last_ns = process.last_ns.max(event.timestamp_ns);
                process.exited = true;
                process.exit_code = Some(code as i64);
                self.changed = true;
            }
        }
    }

    /// How many distinct processes are tracked so far.
    pub fn tracked_count(&self) -> usize {
        self.processes.len()
    }

    /// True when `pid` is already tracked.
    pub fn tracks(&self, pid: u32) -> bool {
        self.processes.contains_key(&pid)
    }

    /// True once since the last call when the tree changed.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// Processes with captured activity, plus their ancestors so the tree
    /// stays connected.
    pub fn list(&self) -> Vec<CaptureProcess> {
        let mut keep = std::collections::BTreeSet::new();
        for process in self.processes.values().filter(|p| p.packets > 0) {
            let mut pid = process.pid;
            while pid != 0 && keep.insert(pid) {
                pid = self.processes.get(&pid).map_or(0, |p| p.parent_pid);
            }
        }
        keep.iter()
            .filter_map(|pid| self.processes.get(pid).cloned())
            .collect()
    }
}

#[cfg(test)]
mod ordering_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{api::FieldSummary, observation::GuestProcessIdentity};

    pub(super) fn header(pid: u32, phase: u8, fragment: u8) -> Header {
        Header {
            root_task_cookie: 0,
            capture_cookie: 1,
            record_type: 1,
            flags: 0,
            schema_id: 1,
            stream_id: 1,
            task_cookie: 1,
            call_id: 1,
            event_seq: 1,
            packet_seq: 1,
            timestamp_ns: 100,
            pid,
            tid: pid,
            cpu: 0,
            syscall_nr: 0,
            abi: 1,
            phase,
            fragment,
            object_id: 0,
            object_offset: 0,
            object_total: 0,
        }
    }

    pub(super) fn event(pid: u32, phase: u8, nr: u64, fields: &[(&str, Vec<u8>)]) -> EventSummary {
        EventSummary {
            root_task_cookie: 0,
            stream_id: 1,
            task_cookie: 1,
            call_id: 1,
            event_seq: 1,
            phase,
            syscall_nr: nr,
            syscall_name: crate::syscalls::name(nr),
            pid,
            tid: pid,
            cpu: 0,
            timestamp_ns: 0,
            args: None,
            result: None,
            complete: true,
            issues: Vec::new(),
            fields: fields
                .iter()
                .map(|(key, preview)| FieldSummary {
                    arg: None,
                    object_id: 1,
                    key: (*key).into(),
                    layout: String::new(),
                    logical_len: None,
                    captured_len: preview.len() as u64,
                    status: None,
                    capture_error: 0,
                    complete: true,
                    preview: preview.clone(),
                    raw_path: None,
                    ranges: Vec::new(),
                    recapture: None,
                    encoding: None,
                })
                .collect(),
        }
    }

    fn identity(tgid: u32) -> GuestProcessIdentity {
        GuestProcessIdentity {
            boot_id: String::new(),
            task_cookie: 0,
            tgid,
            start_boot_ns: 0,
        }
    }

    #[test]
    fn fork_exec_and_exit_build_a_named_tree() {
        let mut tracker = ProcessTracker::default();
        tracker.seed(&[GuestProcess {
            identity: identity(100),
            parent_tgid: 1,
            uid: 0,
            gid: 0,
            thread_count: 1,
            command: "bash".into(),
        }]);
        tracker.packet(&header(100, 1, 1));
        tracker.event(&event(
            100,
            3,
            0,
            &[("lifecycle.child_tgid", 200u64.to_le_bytes().to_vec())],
        ));
        tracker.event(&event(
            200,
            1,
            59,
            &[("arg0.path", b"/usr/bin/ls\0".to_vec())],
        ));
        tracker.event(&event(
            200,
            3,
            0,
            &[("lifecycle.exec_commit", 200u64.to_le_bytes().to_vec())],
        ));
        tracker.packet(&header(200, 1, 1));
        tracker.event(&event(
            200,
            3,
            0,
            &[("lifecycle.task_exit", 0u64.to_le_bytes().to_vec())],
        ));
        let list = tracker.list();
        assert_eq!(list.len(), 2);
        let child = list.iter().find(|p| p.pid == 200).unwrap();
        assert_eq!(child.parent_pid, 100);
        assert_eq!(child.name, "ls");
        assert_eq!(child.exe.as_deref(), Some("/usr/bin/ls"));
        assert_eq!(child.calls, 1);
        assert!(child.exited);
        let parent = list.iter().find(|p| p.pid == 100).unwrap();
        assert!(parent.at_start);
        assert_eq!(parent.name, "bash");
    }

    #[test]
    fn an_exec_path_recaptured_at_exit_names_the_process() {
        let mut tracker = ProcessTracker::default();
        tracker.packet(&header(200, 1, 1));
        // The Entry could not read the path (NOT_RESIDENT): no bytes.
        tracker.event(&event(200, 1, 59, &[("arg0.path", Vec::new())]));
        tracker.event(&event(
            200,
            3,
            0,
            &[("lifecycle.exec_commit", 200u64.to_le_bytes().to_vec())],
        ));
        let mut failed = event(200, 2, 59, &[("arg0.path", b"/tmp/.y\0".to_vec())]);
        failed.fields[0].recapture = Some(crate::api::Recapture::AtExit);
        failed.result = Some(-2);
        tracker.event(&failed);
        assert!(tracker.list()[0].exe.is_none());
        let mut exit = event(200, 2, 59, &[("arg0.path", b"/tmp/.x\0".to_vec())]);
        exit.result = Some(0);
        tracker.event(&exit);
        assert!(
            tracker.list()[0].exe.is_none(),
            "an unmarked Exit field is not a path"
        );
        exit.fields[0].recapture = Some(crate::api::Recapture::KernelCopy);
        tracker.event(&exit);
        let process = &tracker.list()[0];
        assert_eq!(process.name, ".x");
        assert_eq!(process.exe.as_deref(), Some("/tmp/.x"));
    }

    #[test]
    fn launched_programs_are_named_after_their_path_once() {
        let mut tracker = ProcessTracker::default();
        tracker.packet(&header(300, 1, 1));
        assert!(tracker.unnamed(300));
        tracker.name_launched(300, "/tmp/sample");
        tracker.name_launched(300, "/bin/other");
        let process = &tracker.list()[0];
        assert_eq!(process.name, "sample");
        assert_eq!(process.exe.as_deref(), Some("/tmp/sample"));
        assert!(!tracker.unnamed(300));
    }

    #[test]
    fn idle_processes_are_listed_only_as_ancestors() {
        let mut tracker = ProcessTracker::default();
        let process = |tgid, parent| GuestProcess {
            identity: identity(tgid),
            parent_tgid: parent,
            uid: 0,
            gid: 0,
            thread_count: 1,
            command: format!("p{tgid}"),
        };
        tracker.seed(&[
            process(1, 0),
            process(10, 1),
            process(20, 10),
            process(30, 1),
        ]);
        tracker.packet(&header(20, 1, 1));
        let pids: Vec<_> = tracker.list().iter().map(|p| p.pid).collect();
        assert_eq!(pids, [1, 10, 20]);
    }
}
