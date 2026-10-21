// SPDX-License-Identifier: MIT
//! What a file call did, by operation: the categories behind the Files tabs,
//! each call's result, and how the call reached the file.
//!
//! One call can belong to several categories (an `open` with `O_CREAT|O_TRUNC`
//! that made the file is Opened, Created and Truncated). The classification
//! reads the call and the path state before that call is tracked.
//!
//! TODO(io_uring): `IORING_OP_OPENAT`, `WRITE`, `UNLINKAT`, `RENAMEAT` and
//! friends are not mapped. The saved async observations carry no decoded
//! opcode, path or descriptor fields that this index could classify.
use super::file_location::{self, Location};
use super::sigma_events::{O_CREAT, O_TMPFILE, O_TRUNC};
use super::*;
use antinomie_monitor_core::kernel_notes::HashKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Category {
    Opened,
    Created,
    Read,
    Written,
    Truncated,
    Deleted,
    Renamed,
    Linked,
    Permissions,
    Timestamps,
    Xattrs,
    Copied,
    Executed,
    Mapped,
    Probed,
    DirListing,
    Watched,
}

impl Category {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Opened => "Opened",
            Self::Created => "Created",
            Self::Read => "Read",
            Self::Written => "Written",
            Self::Truncated => "Truncated / resized",
            Self::Deleted => "Deleted",
            Self::Renamed => "Renamed / moved",
            Self::Linked => "Linked",
            Self::Permissions => "Permissions & owner",
            Self::Timestamps => "Timestamps",
            Self::Xattrs => "Extended attributes",
            Self::Copied => "Copied",
            Self::Executed => "Executed",
            Self::Mapped => "Mapped",
            Self::Probed => "Metadata probed",
            Self::DirListing => "Directory listing",
            Self::Watched => "Watched / locked",
        }
    }

    /// The tab a category is listed under.
    pub(super) fn tab(self) -> FileTab {
        match self {
            Self::Opened => FileTab::Opened,
            Self::Created => FileTab::Created,
            Self::Read => FileTab::Read,
            Self::Written | Self::Truncated => FileTab::Written,
            Self::Deleted => FileTab::Deleted,
            Self::Renamed => FileTab::Renamed,
            Self::Executed => FileTab::Executed,
            Self::Permissions | Self::Timestamps | Self::Xattrs => FileTab::Attributes,
            Self::Probed => FileTab::Probed,
            Self::Linked | Self::Copied | Self::Mapped | Self::DirListing | Self::Watched => {
                FileTab::Other
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Hit {
    pub category: Category,
    /// Only the first sighting of the path says it is new.
    pub inferred: bool,
}

impl Hit {
    pub(super) fn label(self) -> String {
        if self.inferred {
            format!("{} (inferred)", self.category.label())
        } else {
            self.category.label().to_owned()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Succeeded,
    /// A kernel error, as the negative return.
    Failed(i64),
    NoExit,
}

pub(super) fn outcome(call: &InvocationSummary) -> Outcome {
    match call.exit.as_ref().and_then(|exit| exit.result) {
        None => Outcome::NoExit,
        Some(ret) if (-4095..0).contains(&ret) => Outcome::Failed(ret),
        Some(_) => Outcome::Succeeded,
    }
}

impl Outcome {
    pub(super) fn failed(self) -> bool {
        matches!(self, Self::Failed(_))
    }
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed(_) => "failed",
            Self::NoExit => "no exit",
        }
    }
    pub(super) fn errno(self) -> Option<&'static str> {
        match self {
            Self::Failed(ret) => crate::values::errno_name(ret.unsigned_abs()),
            _ => None,
        }
    }
    pub(super) fn label(self) -> String {
        match self {
            Self::Succeeded => "Succeeded".into(),
            Self::Failed(ret) => match self.errno() {
                Some(name) => format!("Failed ({name})"),
                None => format!("Failed ({ret})"),
            },
            Self::NoExit => "No exit".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    ByPath,
    ByDescriptor,
    /// A descriptor this run never saw opened, or no descriptor at all.
    Inherited,
}

impl Access {
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::ByPath => "path",
            Self::ByDescriptor => "descriptor",
            Self::Inherited => "inherited",
        }
    }
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::ByPath => "By path",
            Self::ByDescriptor => "By descriptor",
            Self::Inherited => "Inherited or unknown descriptor",
        }
    }
}

pub(super) fn access(files: &FdState, call: &InvocationSummary, event: &EventSummary) -> Access {
    if !path_list(call).is_empty() || event.syscall_name == "memfd_create" {
        return Access::ByPath;
    }
    let Some(fd) = fd_argument(call, event) else {
        return Access::Inherited;
    };
    let owner = table_owner(files, call.task_cookie, event.tid);
    // A registered descriptor of an io_uring ring is still a descriptor of a
    // file the run opened, which the guest's file identity names.
    if files.opened.contains_key(&(owner.0, owner.1, fd)) || identity_path(files, call).is_some() {
        Access::ByDescriptor
    } else {
        Access::Inherited
    }
}

const READS: &[&str] = &["read", "pread64", "readv", "preadv", "preadv2"];
const WRITES: &[&str] = &["write", "pwrite64", "writev", "pwritev", "pwritev2"];
const PROBES: &[&str] = &[
    "stat",
    "fstat",
    "lstat",
    "newfstatat",
    "stat64",
    "lstat64",
    "fstat64",
    "fstatat64",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
];
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;

/// Locking `fcntl` commands: GETLK, SETLK, SETLKW and the open-file-description forms.
fn lock_command(command: u64) -> bool {
    matches!(command, 5..=7 | 36..=38)
}

/// Every category a call belongs to, whatever its result. Created also needs
/// the call to have succeeded, because only success shows the file was made.
/// Call before the call is tracked: the Created inference needs the path as
/// it was before this call.
pub(super) fn classify(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
) -> Vec<Hit> {
    let name = event.syscall_name.as_str();
    let args = call_args(call);
    let arg = |index: usize| args.map_or(0, |args| args[index]);
    let hit = |category| Hit {
        category,
        inferred: false,
    };
    match name {
        "open" | "openat" | "openat2" | "creat" => {
            let mut hits = vec![hit(Category::Opened)];
            let flags = open_flags(call, event).unwrap_or(0);
            if let Some(created) = sigma_events::creation(files, call, event, true) {
                let certain = flags & O_TMPFILE == O_TMPFILE || created.inferred.is_empty();
                hits.push(Hit {
                    category: Category::Created,
                    inferred: !certain,
                });
            }
            // A file this call made had nothing to cut.
            if flags & O_TRUNC != 0 && !outcome(call).failed() && hits.len() == 1 {
                hits.push(hit(Category::Truncated));
            }
            hits
        }
        "memfd_create" | "mkdir" | "mkdirat" | "mknod" | "mknodat" => vec![hit(Category::Created)],
        _ if READS.contains(&name) => vec![hit(Category::Read)],
        _ if WRITES.contains(&name) => vec![hit(Category::Written)],
        "truncate" | "ftruncate" | "fallocate" => vec![hit(Category::Truncated)],
        "unlink" | "unlinkat" | "rmdir" => vec![hit(Category::Deleted)],
        "rename" | "renameat" | "renameat2" => vec![hit(Category::Renamed)],
        "link" | "linkat" | "symlink" | "symlinkat" => vec![hit(Category::Linked)],
        "chmod" | "fchmod" | "fchmodat" | "fchmodat2" | "chown" | "fchown" | "lchown"
        | "fchownat" => vec![hit(Category::Permissions)],
        "utime" | "utimes" | "utimensat" | "futimesat" => vec![hit(Category::Timestamps)],
        "setxattr" | "lsetxattr" | "fsetxattr" | "removexattr" | "lremovexattr"
        | "fremovexattr" | "setxattrat" | "removexattrat" => vec![hit(Category::Xattrs)],
        "sendfile" | "copy_file_range" | "splice" => vec![hit(Category::Copied)],
        "ioctl" if files::reflink(name, args) => vec![hit(Category::Copied)],
        "execve" | "execveat" => vec![hit(Category::Executed)],
        "mmap" | "mmap2" => {
            let file_backed = arg(3) & MAP_ANONYMOUS == 0;
            let shared_write = arg(2) & PROT_WRITE != 0 && arg(3) & MAP_PRIVATE == 0;
            if file_backed && (arg(2) & PROT_EXEC != 0 || shared_write) {
                vec![hit(Category::Mapped)]
            } else {
                Vec::new()
            }
        }
        "mprotect" if arg(2) & PROT_EXEC != 0 => vec![hit(Category::Mapped)],
        "msync" => vec![hit(Category::Mapped)],
        _ if PROBES.contains(&name) => vec![hit(Category::Probed)],
        "getdents" | "getdents64" | "readdir" => vec![hit(Category::DirListing)],
        "inotify_add_watch" | "fanotify_mark" | "flock" => vec![hit(Category::Watched)],
        "fcntl" if lock_command(arg(1)) => vec![hit(Category::Watched)],
        _ => Vec::new(),
    }
}

/// A `chmod` or `fchmod` family call's mode.
pub(super) fn mode_argument(call: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(call)?;
    match event.syscall_name.as_str() {
        "chmod" | "fchmod" => Some(args[1] & 0o7777),
        "fchmodat" | "fchmodat2" => Some(args[2] & 0o7777),
        _ => None,
    }
}

/// Mode bits worth pointing out.
pub(super) fn mode_flags(mode: u64) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if mode & 0o4000 != 0 {
        flags.push("setuid");
    }
    if mode & 0o2000 != 0 {
        flags.push("setgid");
    }
    if mode & 0o1000 != 0 {
        flags.push("sticky");
    }
    if mode & 0o111 != 0 {
        flags.push("+x");
    }
    flags
}

/// `uid:gid` of a `chown` family call; `-1` leaves that id as it was.
fn owner_text(call: &InvocationSummary, event: &EventSummary) -> Option<String> {
    let args = call_args(call)?;
    let (user, group) = match event.syscall_name.as_str() {
        "chown" | "fchown" | "lchown" => (args[1], args[2]),
        "fchownat" => (args[2], args[3]),
        _ => return None,
    };
    let id = |id: u64| {
        if id as u32 == u32::MAX {
            "unchanged".to_owned()
        } else {
            (id as u32).to_string()
        }
    };
    Some(format!("owner {} group {}", id(user), id(group)))
}

fn flock_text(operation: u64) -> &'static str {
    match operation & 0xf {
        1 => "shared lock",
        2 => "exclusive lock",
        8 => "unlock",
        _ => "lock operation",
    }
}

/// What an exec of a script shows when the guest did not record which
/// interpreter it named (a guest from before the exec image record).
const SCRIPT_NOTE: &str = "script run through its interpreter, path not recorded";

/// "script run through /bin/sh" and, when the file loaded is somewhere else
/// (a symlink, a multi-call binary), where: "script run through /bin/sh (loaded
/// /usr/bin/busybox)". `None` for a program that is not a script.
fn script_note(call: &InvocationSummary) -> Option<String> {
    let hash_says =
        kernel_records::file_hash(call, HashKind::Exec).is_some_and(|hash| hash.interpreter);
    let image = kernel_records::exec_image(call);
    let named = image
        .as_ref()
        .is_some_and(|image| image.interpreter.is_some() || image.interpreter_truncated);
    if !hash_says && !named {
        return None;
    }
    let Some(image) = image.filter(|_| named) else {
        return Some(SCRIPT_NOTE.into());
    };
    Some(match (image.interpreter, image.path) {
        (Some(name), Some(path)) if path != name => {
            format!("script run through {name} (loaded {path})")
        }
        (Some(name), _) => format!("script run through {name}"),
        (None, _) => "script run through an interpreter whose name was too long to record".into(),
    })
}

/// Words for a row's Detail column. Empty when the syscall name says it all.
pub(super) fn detail(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    hit: Hit,
) -> String {
    let name = event.syscall_name.as_str();
    let args = call_args(call);
    let arg = |index: usize| args.map_or(0, |args| args[index]);
    let used = sigma_events::paths(files, call, event);
    let path_of = |role: sigma_events::Role| {
        used.iter()
            .find(|used| used.role == role)
            .map(|used| used.name.clone())
    };
    let joined = || path_list(call).join(" → ");
    match hit.category {
        Category::Opened => open_flags(call, event)
            .map(|flags| {
                let mut text = match flags & 3 {
                    0 => "read",
                    1 => "write",
                    2 => "read/write",
                    _ => "unknown access",
                }
                .to_owned();
                for (bit, label) in [
                    (O_CREAT, "O_CREAT"),
                    (O_TRUNC, "O_TRUNC"),
                    (0x400, "O_APPEND"),
                ] {
                    if flags & bit != 0 {
                        text.push_str(&format!(", {label}"));
                    }
                }
                if flags & O_TMPFILE == O_TMPFILE {
                    text.push_str(", O_TMPFILE");
                }
                text
            })
            .unwrap_or_default(),
        Category::Created => {
            if hit.inferred {
                "path not seen earlier in this run".into()
            } else {
                String::new()
            }
        }
        Category::Written => ret_text(call, "bytes written"),
        Category::Read => ret_text(call, "bytes read"),
        Category::Truncated => match name {
            "truncate" | "ftruncate" => format!("length {}", arg(1)),
            "fallocate" => format!("mode {:#x} offset {} length {}", arg(1), arg(2), arg(3)),
            _ => "O_TRUNC".into(),
        },
        Category::Deleted => {
            if name == "rmdir" || (name == "unlinkat" && arg(2) & 0x200 != 0) {
                "directory".into()
            } else {
                String::new()
            }
        }
        Category::Renamed => {
            let old = path_of(sigma_events::Role::Old);
            let new = path_of(sigma_events::Role::New);
            let mut text = match (&old, &new) {
                (Some(old), Some(new)) => format!("{old} → {new}"),
                _ => joined(),
            };
            if name == "renameat2" && arg(4) & 2 != 0 {
                text.push_str(" (exchange)");
            } else if new.as_deref().is_some_and(|new| files.journal.knows(new)) {
                text.push_str(" (destination seen earlier; overwritten)");
            }
            text
        }
        Category::Linked => {
            let kind = if name.starts_with("sym") {
                "symbolic link"
            } else {
                "hard link"
            };
            format!("{kind}: {}", joined())
        }
        Category::Permissions => match mode_argument(call, event) {
            Some(mode) => {
                let flags = mode_flags(mode);
                if flags.is_empty() {
                    format!("mode {mode:04o}")
                } else {
                    format!("mode {mode:04o} ({})", flags.join(", "))
                }
            }
            None => owner_text(call, event).unwrap_or_default(),
        },
        Category::Timestamps => {
            let times = match name {
                "utimensat" | "futimesat" => arg(2),
                _ => arg(1),
            };
            if times == 0 {
                "set to the current time".into()
            } else {
                "set to explicit times".into()
            }
        }
        Category::Xattrs => {
            let action = if name.contains("remove") {
                "removed"
            } else {
                "set"
            };
            let attribute = call
                .entry
                .iter()
                .chain(call.exit.iter())
                .flat_map(|event| &event.fields)
                .filter(|field| field.key.ends_with(".name"))
                .find_map(path_text);
            match attribute {
                Some(attribute) => format!("{action} {attribute}"),
                None => action.into(),
            }
        }
        Category::Copied => {
            let owner = table_owner(files, call.task_cookie, event.tid);
            let source = files::transfer_source(name, args)
                .and_then(|fd| files.opened.get(&(owner.0, owner.1, fd)))
                .map_or_else(|| "unknown source".into(), Clone::clone);
            let destination = displayed_path(call, event, files);
            format!("{source} → {destination}")
        }
        Category::Executed => {
            let line = normalized::command_line(call, event).unwrap_or_default();
            // The exec image record names the interpreter the script's #! line
            // gave. A guest from before it records only that the image it
            // hashed was a script's interpreter.
            match (script_note(call), line.is_empty()) {
                (None, _) => line,
                (Some(note), true) => note,
                (Some(note), false) => format!("{line} ({note})"),
            }
        }
        Category::Mapped => match name {
            "msync" => "shared mapping written back".into(),
            "mprotect" => "mapping made executable".into(),
            _ if arg(2) & PROT_EXEC != 0 => "executable mapping".into(),
            _ => "shared writable mapping".into(),
        },
        Category::Probed | Category::DirListing => String::new(),
        Category::Watched => match name {
            "flock" => flock_text(arg(1)).into(),
            "fcntl" => "record lock".into(),
            "inotify_add_watch" => format!("mask {:#x}", arg(2)),
            _ => format!("mask {:#x}", arg(2)),
        },
    }
}

fn ret_text(call: &InvocationSummary, what: &str) -> String {
    match call.exit.as_ref().and_then(|exit| exit.result) {
        Some(ret) if ret >= 0 => format!("{ret} {what}"),
        _ => String::new(),
    }
}

/// The step a call adds to its file's lifecycle, when it is one worth telling.
/// `mode` is the last mode a chmod set, to tell a new `+x` from a repeat.
pub(super) fn step_label(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    hit: Hit,
    mode: &mut Option<u64>,
) -> Option<String> {
    let name = event.syscall_name.as_str();
    let arg = |index: usize| call_args(call).map_or(0, |args| args[index]);
    Some(match hit.category {
        Category::Created => hit.label().to_lowercase(),
        Category::Written => "written".into(),
        Category::Truncated => "truncated".into(),
        Category::Deleted => match kernel_records::file_id(call) {
            // The guest counted the links left: the file is gone only at none.
            Some(id) if id.nlink > 0 && !id.directory => format!(
                "name removed ({} link{} remain{})",
                id.nlink,
                if id.nlink == 1 { "" } else { "s" },
                if id.nlink == 1 { "s" } else { "" }
            ),
            _ => "deleted".into(),
        },
        Category::Renamed => {
            let new = sigma_events::paths(files, call, event)
                .into_iter()
                .find(|used| used.role == sigma_events::Role::New);
            match new {
                Some(new) => format!("renamed → {}", new.name),
                None => "renamed".into(),
            }
        }
        Category::Linked => {
            let new = sigma_events::paths(files, call, event)
                .into_iter()
                .find(|used| used.role == sigma_events::Role::New);
            let kind = if name.starts_with("sym") {
                "symlinked"
            } else {
                "hard-linked"
            };
            match new {
                Some(new) => format!("{kind} → {}", new.name),
                None => kind.into(),
            }
        }
        Category::Permissions => match mode_argument(call, event) {
            None => "chown".into(),
            Some(new) => {
                let before = mode.replace(new);
                let flags = mode_flags(new);
                let gained_x = flags.contains(&"+x") && !before.is_some_and(|old| old & 0o111 != 0);
                if flags.contains(&"setuid") {
                    "chmod setuid".into()
                } else if flags.contains(&"setgid") {
                    "chmod setgid".into()
                } else if gained_x {
                    "chmod +x".into()
                } else if let Some(old) = before.filter(|old| *old != new) {
                    format!("chmod {old:04o} → {new:04o}")
                } else {
                    format!("chmod {new:04o}")
                }
            }
        },
        Category::Timestamps => "timestamps set".into(),
        Category::Xattrs => "xattr changed".into(),
        Category::Copied => "copied into".into(),
        Category::Executed => "executed".into(),
        Category::Mapped => match name {
            "msync" => "mapping synced".into(),
            _ if arg(2) & PROT_EXEC != 0 => "mapped executable".into(),
            _ => "mapped shared".into(),
        },
        Category::Opened
        | Category::Read
        | Category::Probed
        | Category::DirListing
        | Category::Watched => return None,
    })
}

/// The sample's own image paths: every image the root process ran.
pub(super) fn own_images(files: &FdState) -> Vec<String> {
    let mut images = Vec::new();
    for node in files.process_images.values().filter(|node| node.root) {
        for image in node.exec_history.iter().chain([&node.comm]) {
            if image.starts_with('/') && !images.contains(image) {
                images.push(image.clone());
            }
        }
    }
    images
}

/// The classes of every path a call names.
pub(super) fn locations(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
) -> Vec<Location> {
    let own = own_images(files);
    let mut names: Vec<String> = sigma_events::paths(files, call, event)
        .into_iter()
        .map(|used| used.name)
        .collect();
    if names.is_empty() {
        if let Some((path, _)) = sigma_events::clean(&displayed_path(call, event, files)) {
            names.push(path);
        }
    }
    let mut found = Vec::new();
    for name in &names {
        for location in file_location::classify(name, &own) {
            if !found.contains(&location) {
                found.push(location);
            }
        }
    }
    found.sort();
    found
}

pub(super) fn location_text(found: &[Location]) -> String {
    if found.is_empty() {
        "—".into()
    } else {
        found
            .iter()
            .map(|location| location.label())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The Location cell: warn-coloured when the path is one a reader should look
/// at first (hidden, persistence, credentials).
pub(super) fn location_cell(found: &[Location]) -> Cell {
    let color = if found.iter().any(|location| location.flagged()) {
        theme::warn()
    } else {
        theme::text()
    };
    cell(location_text(found), color, false)
}

/// Whether a row's `file.location` values include a flagged class.
pub(super) fn row_flagged(values: &[(&str, RowValue)]) -> bool {
    values.iter().any(|(key, value)| match (*key, value) {
        ("file.location", RowValue::List(tags)) => tags
            .iter()
            .any(|tag| matches!(tag.as_str(), "hidden" | "persistence" | "credentials")),
        _ => false,
    })
}

/// Values every file row carries for filters, besides its own fields.
pub(super) fn cross_values(
    outcome: Outcome,
    access: Access,
    locations: &[Location],
) -> Vec<(&'static str, RowValue)> {
    vec![
        ("file.result", RowValue::Text(outcome.tag().into())),
        (
            "file.errno",
            outcome
                .errno()
                .map_or(RowValue::Missing, |name| RowValue::Text(name.into())),
        ),
        ("file.access_by", RowValue::Text(access.tag().into())),
        (
            "file.location",
            RowValue::List(locations.iter().map(|l| l.tag().to_owned()).collect()),
        ),
    ]
}

/// Table columns of every operation tab.
pub(super) const EVENT_HEADERS: &[&str] = &[
    "Time",
    "Category",
    "Operation",
    "Path",
    "Detail",
    "Process (PID / TID)",
    "Result",
    "Location",
    "Access",
    "Evidence",
];

/// One operation-tab row. The first cell holds the filterable values.
pub(super) fn category_row(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    hit: Hit,
) -> Vec<Cell> {
    let base = file_events::event_row(files, call, event);
    let result = outcome(call);
    let access = access(files, call, event);
    let found = locations(files, call, event);
    let text = detail(files, call, event, hit);
    let mut values = base[0].values.clone();
    values.extend(cross_values(result, access, &found));
    values.push((
        "file.category",
        RowValue::List(vec![hit.category.label().to_owned()]),
    ));
    values.push(("file.detail", RowValue::Text(text.clone())));
    values.push((
        "file.interpreter",
        kernel_records::exec_image(call)
            .and_then(|image| image.interpreter)
            .filter(|_| hit.category == Category::Executed)
            .map_or(RowValue::Missing, RowValue::Text),
    ));
    values.push((
        "file.created_inferred",
        RowValue::Bool(hit.category == Category::Created && hit.inferred),
    ));
    let mode = mode_argument(call, event).filter(|_| hit.category == Category::Permissions);
    values.push((
        "file.mode",
        mode.map_or(RowValue::Missing, |mode| {
            RowValue::Text(format!("{mode:04o}"))
        }),
    ));
    values.push((
        "file.mode_flags",
        mode.map_or(RowValue::Missing, |mode| {
            RowValue::List(mode_flags(mode).into_iter().map(str::to_owned).collect())
        }),
    ));
    let notable = mode.is_some_and(|mode| mode & 0o7111 != 0);
    let mut row = vec![
        cell(event.timestamp_ns.to_string(), theme::text(), true),
        cell(hit.label(), theme::text(), false),
        cell(
            file_events::operation_label(call, event),
            theme::value(theme::ValueKind::Name),
            false,
        ),
        cell(base[0].text.clone(), theme::text(), true),
        cell(
            text,
            if notable {
                theme::warn()
            } else {
                theme::text()
            },
            false,
        ),
        cell(base[1].text.clone(), theme::text(), true),
        cell(
            result.label(),
            if result.failed() {
                theme::warn()
            } else {
                theme::text()
            },
            false,
        ),
        location_cell(&found),
        cell(access.label(), theme::text(), false),
        cell(format!("call {}", call.call_id), theme::text(), true),
    ];
    row[0].values = values;
    row
}

/// Show guest time in the first column of rows that carry their raw time.
pub(super) fn with_time(
    rows: &[Vec<Cell>],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Vec<Vec<Cell>> {
    let mut rows = rows.to_vec();
    for row in &mut rows {
        row[0].text =
            crate::time_format::guest_ns(clock, files::number(&row[0].values, "event.time_ns"));
    }
    rows
}

/// Filterable fields of every file table.
pub(super) const FILE_FIELDS: &[crate::query::FieldSpec<'static>] = &[
    crate::query::FieldSpec::text(
        "process.exe",
        "Captured executable active at this file operation",
    ),
    crate::query::FieldSpec::boolean(
        "file.standard_io",
        "Changed-file group contains only operations on stdin/stdout/stderr",
    ),
    crate::query::FieldSpec::number(
        "file.diff_count",
        "Known differing bytes; gaps are separate",
    ),
    crate::query::FieldSpec::boolean(
        "file.complete",
        "Original and final contents fully available",
    ),
    crate::query::FieldSpec::number("file.read_size", "Successful read length"),
    crate::query::FieldSpec::text("file.content", "Captured transferred content preview"),
    crate::query::FieldSpec::text(
        "file.path",
        "Path as displayed; inferred names label their uncertainty",
    ),
    crate::query::FieldSpec::text("file.old_path", "Captured old rename path"),
    crate::query::FieldSpec::text("file.new_path", "Captured new rename path"),
    crate::query::FieldSpec::number(
        "file.fd",
        "Observed descriptor; missing without success/provenance",
    ),
    crate::query::FieldSpec::text("file.operation", "Observed syscall operation"),
    crate::query::FieldSpec::text(
        "file.via",
        "syscall, or io_uring / AIO for a request read as the call it stands for",
    ),
    crate::query::FieldSpec::text(
        "file.inode",
        "Device:inode the guest recorded for the file; the same on every name",
    ),
    crate::query::FieldSpec::tags(
        "file.names",
        "Every name a changed file was seen under (renames, hard links)",
    ),
    crate::query::FieldSpec::text(
        "file.interpreter",
        "Interpreter a script's #! line named, for an Executed script",
    ),
    crate::query::FieldSpec::text("file.access", "Requested access/creation flags"),
    crate::query::FieldSpec::boolean(
        "file.success",
        "Observed syscall outcome; missing without exit",
    ),
    crate::query::FieldSpec::number(
        "file.written_size",
        "Successful written octets, not requested length",
    ),
    crate::query::FieldSpec::number(
        "file.requested_size",
        "Requested scalar write length in octets",
    ),
    crate::query::FieldSpec::number("file.offset", "Captured pwrite offset in octets"),
    crate::query::FieldSpec::number("file.count", "One observed operation per evidence row"),
    crate::query::FieldSpec::number("process.pid", "Observed PID"),
    crate::query::FieldSpec::number("process.tid", "Observed TID"),
    crate::query::FieldSpec::number("process.cookie", "Stable task cookie"),
    crate::query::FieldSpec::number("event.id", "Original invocation ID"),
    crate::query::FieldSpec::number("stream.id", "Recorded stream identity"),
    crate::query::FieldSpec::number("event.time_ns", "Guest monotonic nanoseconds"),
    crate::query::FieldSpec::number("syscall.ret", "Signed observed exit result"),
    crate::query::FieldSpec::tags(
        "file.category",
        "Operation categories: Created, Written, Deleted, Renamed / moved, Executed ...",
    ),
    crate::query::FieldSpec::text("file.detail", "Operation detail, such as old → new"),
    crate::query::FieldSpec::text("file.result", "succeeded, failed or no exit"),
    crate::query::FieldSpec::text("file.errno", "Error name of a failed call, such as ENOENT"),
    crate::query::FieldSpec::tags(
        "file.location",
        "Path classes: persistence, credentials, system, temp, pseudo-fs, self, hidden",
    ),
    crate::query::FieldSpec::text(
        "file.access_by",
        "path, descriptor, or inherited for a descriptor not opened in this run",
    ),
    crate::query::FieldSpec::boolean(
        "file.created_inferred",
        "Created only because the path was not seen earlier",
    ),
    crate::query::FieldSpec::text("file.mode", "Mode set by chmod, in octal"),
    crate::query::FieldSpec::tags(
        "file.mode_flags",
        "setuid, setgid, sticky or +x in the mode",
    ),
    crate::query::FieldSpec::text(
        "file.lifecycle",
        "Per-file sequence, such as created → written",
    ),
    crate::query::FieldSpec::number(
        "file.failed_attempts",
        "Failed change attempts on this file, not counted as changes",
    ),
];
