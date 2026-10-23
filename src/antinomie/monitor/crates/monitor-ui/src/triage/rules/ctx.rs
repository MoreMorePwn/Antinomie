// SPDX-License-Identifier: GPL-3.0-only
//! What a rule sees of one call: its numbers, the paths it names resolved as far
//! as the trace allows, its argument vector and the state before it ran.
use super::super::file_category::{self, Category as Op};
use super::super::sigma_events::{self, Role};
use super::super::*;
use std::cell::OnceCell;

/// x86-64 system call numbers the rules use.
pub(super) mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const IOCTL: u64 = 16;
    pub const NANOSLEEP: u64 = 35;
    pub const SOCKET: u64 = 41;
    pub const CONNECT: u64 = 42;
    pub const ACCEPT: u64 = 43;
    pub const SENDTO: u64 = 44;
    pub const SENDMSG: u64 = 46;
    pub const BIND: u64 = 49;
    pub const LISTEN: u64 = 50;
    pub const SETSOCKOPT: u64 = 54;
    pub const EXECVE: u64 = 59;
    pub const KILL: u64 = 62;
    pub const SYSINFO: u64 = 99;
    pub const PTRACE: u64 = 101;
    pub const SYSLOG: u64 = 103;
    pub const PERSONALITY: u64 = 135;
    pub const MOUNT: u64 = 165;
    pub const REBOOT: u64 = 169;
    pub const INIT_MODULE: u64 = 175;
    pub const PRCTL: u64 = 157;
    pub const CLOCK_NANOSLEEP: u64 = 230;
    pub const TKILL: u64 = 200;
    pub const TGKILL: u64 = 234;
    pub const KEXEC_LOAD: u64 = 246;
    pub const ALARM: u64 = 37;
    pub const UNSHARE: u64 = 272;
    pub const SETNS: u64 = 308;
    pub const PROCESS_VM_READV: u64 = 310;
    pub const PROCESS_VM_WRITEV: u64 = 311;
    pub const FINIT_MODULE: u64 = 313;
    pub const KEXEC_FILE_LOAD: u64 = 320;
    pub const MEMFD_CREATE: u64 = 319;
    pub const SECCOMP: u64 = 317;
    pub const EXECVEAT: u64 = 322;
    pub const PKEY_MPROTECT: u64 = 329;
    pub const PIDFD_SEND_SIGNAL: u64 = 424;
    pub const IO_URING_SETUP: u64 = 425;
    pub const IO_URING_ENTER: u64 = 426;
    pub const TIMERFD_SETTIME: u64 = 286;
    pub const CLONE3: u64 = 435;
    pub const CLONE: u64 = 56;
}

/// A file a call acted on, by what it did to it.
pub(super) struct Touch {
    pub op: Op,
    pub path: String,
    pub role: Role,
}

pub(super) struct Ctx<'a> {
    pub call: &'a InvocationSummary,
    pub event: &'a EventSummary,
    pub files: &'a FdState,
    /// The recording the call came from, for captured bytes past the preview.
    pub dir: Option<&'a Path>,
    pub nr: u64,
    pub name: &'a str,
    pub args: [u64; 6],
    pub ret: Option<i64>,
    pub ok: bool,
    /// The call failed with an error code (not merely missing its exit).
    pub failed: bool,
    /// An io_uring or AIO request standing for a file call.
    pub via_async: bool,
    /// The program the calling task is running, as the trace named it.
    pub image: Option<&'a str>,
    touches: OnceCell<Vec<Touch>>,
    argv: OnceCell<Vec<String>>,
    envp: OnceCell<Vec<String>>,
}

impl<'a> Ctx<'a> {
    pub(super) fn new(
        call: &'a InvocationSummary,
        event: &'a EventSummary,
        files: &'a FdState,
        dir: Option<&'a Path>,
        via_async: bool,
    ) -> Self {
        let ret = call.exit.as_ref().and_then(|exit| exit.result);
        Self {
            call,
            event,
            files,
            dir,
            nr: event.syscall_nr,
            name: event.syscall_name.as_str(),
            args: event.args.or(call_args(call)).unwrap_or([0; 6]),
            ret,
            ok: ret.is_some_and(|ret| ret >= 0),
            failed: ret.is_some_and(|ret| (-4095..0).contains(&ret)),
            via_async,
            image: process_image(files, event),
            touches: OnceCell::new(),
            argv: OnceCell::new(),
            envp: OnceCell::new(),
        }
    }

    /// The program's file name.
    pub(super) fn image_name(&self) -> &str {
        self.image.map_or("", base)
    }

    pub(super) fn is_exec(&self) -> bool {
        matches!(self.nr, nr::EXECVE | nr::EXECVEAT)
    }

    /// The path a descriptor argument refers to, if the run opened it.
    pub(super) fn fd_path(&self, fd: u64) -> Option<&'a str> {
        let owner = table_owner(self.files, self.call.task_cookie, self.event.tid);
        self.files
            .opened
            .get(&(owner.0, owner.1, fd))
            .map(String::as_str)
    }

    pub(super) fn socket(&self, fd: u64) -> Option<&'a sigma_events::Socket> {
        sigma_events::socket_at(self.files, self.call.task_cookie, self.event.tid, fd)
    }

    /// What the call did to which files, with the paths resolved.
    pub(super) fn touches(&self) -> &[Touch] {
        self.touches.get_or_init(|| {
            let hits = file_category::classify(self.files, self.call, self.event);
            if hits.is_empty() {
                return Vec::new();
            }
            let mut used: Vec<(String, Role)> =
                sigma_events::paths(self.files, self.call, self.event)
                    .into_iter()
                    .map(|used| (used.name, used.role))
                    .collect();
            if used.is_empty() {
                let shown = displayed_path(self.call, self.event, self.files);
                if let Some((path, _)) = sigma_events::clean(&shown) {
                    used.push((path, Role::Subject));
                }
            }
            hits.iter()
                .flat_map(|hit| {
                    used.iter().map(|(path, role)| Touch {
                        op: hit.category,
                        path: path.clone(),
                        role: *role,
                    })
                })
                .collect()
        })
    }

    pub(super) fn open_flags(&self) -> Option<u64> {
        open_flags(self.call, self.event)
    }

    /// The call opened or created a file in a way that can change it.
    pub(super) fn opens_for_write(&self) -> bool {
        self.open_flags()
            .is_some_and(|flags| flags & 3 != 0 || flags & (0o100 | 0o1000 | 0o2000) != 0)
    }

    /// The call opened a file in a way that can read it.
    pub(super) fn opens_for_read(&self) -> bool {
        self.open_flags().is_some_and(|flags| flags & 3 != 1)
    }

    /// Files this call changed: created, written, cut, or given a name.
    pub(super) fn changes(&self) -> impl Iterator<Item = &Touch> {
        self.touches().iter().filter(move |touch| match touch.op {
            Op::Created | Op::Written | Op::Truncated => true,
            Op::Opened => self.opens_for_write(),
            Op::Renamed | Op::Linked => touch.role == Role::New,
            _ => false,
        })
    }

    /// Files this call removed or moved away.
    pub(super) fn removes(&self) -> impl Iterator<Item = &Touch> {
        self.touches().iter().filter(|touch| match touch.op {
            Op::Deleted => true,
            Op::Renamed => touch.role == Role::Old,
            _ => false,
        })
    }

    /// Files this call opened or read.
    pub(super) fn reads(&self) -> impl Iterator<Item = &Touch> {
        self.touches().iter().filter(move |touch| match touch.op {
            Op::Opened => self.opens_for_read(),
            Op::Read => true,
            _ => false,
        })
    }

    /// Files this call only looked at, or tried.
    pub(super) fn looks(&self) -> impl Iterator<Item = &Touch> {
        self.touches()
            .iter()
            .filter(|touch| matches!(touch.op, Op::Opened | Op::Probed | Op::Read | Op::Executed))
    }

    /// The path an exec named.
    pub(super) fn exec_path(&self) -> Option<String> {
        if !self.is_exec() {
            return None;
        }
        path_list(self.call)
            .into_iter()
            .next()
            .or_else(|| kernel_records::exec_image(self.call).and_then(|image| image.path))
    }

    /// The arguments of an exec that were captured whole.
    pub(super) fn argv(&self) -> &[String] {
        self.argv.get_or_init(|| {
            normalized::argument_vector(self.call, self.event)
                .map(|vector| vector.arguments.into_iter().flatten().collect())
                .unwrap_or_default()
        })
    }

    /// The environment strings of an exec that were captured whole.
    pub(super) fn envp(&self) -> &[String] {
        self.envp.get_or_init(|| {
            let argument = match self.nr {
                nr::EXECVE => 2,
                nr::EXECVEAT => 3,
                _ => return Vec::new(),
            };
            string_vector(self.call, argument)
        })
    }

    /// The captured field of one argument, by field key suffix.
    pub(super) fn field(
        &self,
        argument: usize,
        suffix: &str,
    ) -> Option<&'a antinomie_monitor_core::FieldSummary> {
        self.call
            .entry
            .iter()
            .chain(self.call.exit.iter())
            .flat_map(|event| &event.fields)
            .find(|field| {
                trace::field_argument(self.nr, field) == Some(argument)
                    && (field.key.ends_with(suffix) || suffix.is_empty())
            })
    }

    /// The bytes captured for one argument's pointee.
    pub(super) fn bytes(&self, argument: usize, suffix: &str) -> Option<&'a [u8]> {
        self.field(argument, suffix)
            .map(trace::covered_preview)
            .filter(|bytes| !bytes.is_empty())
    }

    /// The text of a captured string argument.
    pub(super) fn text(&self, argument: usize) -> Option<String> {
        let field = self.field(argument, "")?;
        let bytes = trace::covered_preview(field);
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
    }

    /// A native-endian 64-bit word at `offset` of an argument's pointee.
    pub(super) fn word(&self, argument: usize, suffix: &str, offset: usize) -> Option<u64> {
        let bytes = self.bytes(argument, suffix)?;
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    }

    /// The socket address the call was given or got back.
    pub(super) fn address(&self, argument: usize) -> Option<sigma_events::Address> {
        sigma_events::address(self.call, self.nr, argument)
    }

    /// The bytes a read returned or a write sent, as far as they were captured.
    pub(super) fn payload(&self, reading: bool) -> Vec<u8> {
        let size = self
            .ret
            .filter(|ret| *ret > 0)
            .map(|ret| ret as u64)
            .unwrap_or(0);
        let want = if reading { size } else { self.args[2] };
        let captured = file_content::capture(self.call, reading, self.dir, want.min(65536));
        let mut bytes = vec![0u8; captured.len().min(65536)];
        let mut longest = 0;
        for (offset, byte) in captured.iter() {
            if let Some(slot) = usize::try_from(offset)
                .ok()
                .and_then(|at| bytes.get_mut(at))
            {
                *slot = byte;
                longest = longest.max(offset as usize + 1);
            }
        }
        bytes.truncate(longest);
        bytes
    }

    /// Evidence the engine records for the first occurrence of a row.
    pub(super) fn time(&self) -> u64 {
        self.event.timestamp_ns
    }
}

/// The last component of a path.
pub(super) fn base(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

/// The directory of a path, without the trailing slash.
pub(super) fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// The strings of a pointer vector captured as `argN.string[i]`.
pub(super) fn string_vector(call: &InvocationSummary, argument: usize) -> Vec<String> {
    let fields: Vec<_> = call
        .entry
        .iter()
        .chain(call.exit.iter())
        .flat_map(|event| &event.fields)
        .collect();
    let mut found = Vec::new();
    for index in 0..512 {
        let key = format!("arg{argument}.string[{index}]");
        let Some(field) = fields.iter().find(|field| field.key == key) else {
            break;
        };
        let bytes = trace::covered_preview(field);
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        found.push(String::from_utf8_lossy(&bytes[..end]).into_owned());
    }
    found
}

/// The path with `/proc/self`, `/proc/thread-self` and `/proc/<own pid>` folded
/// together, so a program naming itself by pid is still itself.
pub(super) fn proc_self(path: &str, pid: u32) -> String {
    let own = format!("/proc/{pid}/");
    if let Some(rest) = path.strip_prefix(&own) {
        format!("/proc/self/{rest}")
    } else if let Some(rest) = path.strip_prefix("/proc/thread-self/") {
        format!("/proc/self/{rest}")
    } else if path == format!("/proc/{pid}") {
        "/proc/self".into()
    } else {
        path.to_owned()
    }
}

/// Whether the path is below one of the directories.
pub(super) fn under(path: &str, directories: &[&str]) -> bool {
    directories.iter().any(|directory| {
        path.strip_prefix(directory).is_some_and(|rest| {
            rest.is_empty() || rest.starts_with('/') || directory.ends_with('/')
        })
    })
}

/// The home directory part of a path: `/home/x` or `/root`, with what follows.
pub(super) fn home_relative(path: &str) -> Option<&str> {
    if let Some(rest) = path.strip_prefix("/root/") {
        return Some(rest);
    }
    let rest = path.strip_prefix("/home/")?;
    rest.split_once('/').map(|(_, rest)| rest)
}
