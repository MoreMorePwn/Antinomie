// SPDX-License-Identifier: GPL-3.0-only
//! The rules that decide whether a watch folder, a subfolder or a file in it
//! may be used at all (design 4.2.1 "Safety", abuse case A11). They work on a
//! plain copy of `stat` and an [`Identity`], so every rule is tested without
//! a second user on the machine.

use rustix::fs::{FileType, Stat};

/// What kind of thing a directory entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Regular,
    Directory,
    Symlink,
    /// A FIFO, a socket, a device.
    Other,
}

/// The parts of `stat` the rules read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

impl From<&Stat> for Facts {
    // The field widths differ between targets; the casts keep one source.
    #[allow(clippy::unnecessary_cast)]
    fn from(stat: &Stat) -> Self {
        let kind = match FileType::from_raw_mode(stat.st_mode as _) {
            FileType::RegularFile => Kind::Regular,
            FileType::Directory => Kind::Directory,
            FileType::Symlink => Kind::Symlink,
            _ => Kind::Other,
        };
        let ns = |sec: i64, nsec: i64| i128::from(sec) * 1_000_000_000 + i128::from(nsec);
        Self {
            kind,
            mode: stat.st_mode as u32 & 0o7777,
            uid: stat.st_uid,
            gid: stat.st_gid,
            nlink: stat.st_nlink as u64,
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            size: stat.st_size.max(0) as u64,
            mtime_ns: ns(stat.st_mtime as i64, stat.st_mtime_nsec as i64),
            ctime_ns: ns(stat.st_ctime as i64, stat.st_ctime_nsec as i64),
        }
    }
}

impl Facts {
    /// The identity of the file itself, whatever its name or content.
    pub fn same_file(&self, other: &Facts) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    /// The same file with the same size and times: nothing was written since.
    pub fn unchanged_since(&self, other: &Facts) -> bool {
        self.same_file(other)
            && self.size == other.size
            && self.mtime_ns == other.mtime_ns
            && self.ctime_ns == other.ctime_ns
    }
}

/// The user the daemon runs as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

impl Identity {
    pub fn current() -> Self {
        let gid = rustix::process::getegid().as_raw();
        let mut groups: Vec<u32> = rustix::process::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(|g| g.as_raw())
            .collect();
        groups.push(gid);
        groups.sort_unstable();
        groups.dedup();
        Self {
            uid: rustix::process::geteuid().as_raw(),
            gid,
            groups,
        }
    }

    pub fn in_group(&self, gid: u32) -> bool {
        self.groups.contains(&gid)
    }
}

/// Why a folder (the watch root or a subfolder) may not be used, or `None`.
///
/// It must be a real directory, owned by the daemon's user (with
/// `allow_group_write`: or by a group the daemon belongs to), writable by no
/// one else. A folder anyone can write to is never used.
pub fn folder_problem(facts: &Facts, me: &Identity, allow_group_write: bool) -> Option<String> {
    if facts.kind != Kind::Directory {
        return Some("not a directory".into());
    }
    if facts.mode & 0o002 != 0 {
        return Some("writable by everyone; a drop folder must not be world-writable".into());
    }
    if facts.mode & 0o020 != 0 && !allow_group_write {
        return Some(
            "writable by its group; set allow_group_write = true for this folder if that is intended"
                .into(),
        );
    }
    if facts.uid != me.uid && !(allow_group_write && me.in_group(facts.gid)) {
        return Some(format!(
            "owned by uid {}, not by the daemon's user (uid {})",
            facts.uid, me.uid
        ));
    }
    None
}

/// Why a file may not be taken, or `None`. `folder_gid` is the group of the
/// folder the file is in.
pub fn file_problem(
    facts: &Facts,
    me: &Identity,
    folder_gid: u32,
    allow_group_write: bool,
) -> Option<String> {
    match facts.kind {
        Kind::Regular => {}
        Kind::Symlink => return Some("a symbolic link".into()),
        Kind::Directory => return Some("a directory".into()),
        Kind::Other => return Some("not a regular file (a device, FIFO or socket)".into()),
    }
    if facts.nlink > 1 {
        return Some(format!(
            "has {} hard links; a file that may also be reached from outside the folder is refused",
            facts.nlink
        ));
    }
    let ours = facts.uid == me.uid;
    let shared = allow_group_write && facts.gid == folder_gid && me.in_group(folder_gid);
    if !ours && !shared {
        return Some(format!(
            "owned by uid {}, not by the daemon's user (uid {})",
            facts.uid, me.uid
        ));
    }
    None
}

/// Names that say a file is still on its way (design 4.2.1 "Stability").
pub fn looks_partial(name: &[u8]) -> bool {
    if name.first() == Some(&b'.') {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    [&b".part"[..], b".tmp", b".crdownload"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Identity {
        Identity {
            uid: 1000,
            gid: 1000,
            groups: vec![1000, 2000],
        }
    }

    fn dir(mode: u32, uid: u32, gid: u32) -> Facts {
        Facts {
            kind: Kind::Directory,
            mode,
            uid,
            gid,
            nlink: 2,
            dev: 1,
            ino: 2,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
        }
    }

    fn file(uid: u32, gid: u32, nlink: u64) -> Facts {
        Facts {
            kind: Kind::Regular,
            mode: 0o644,
            uid,
            gid,
            nlink,
            dev: 1,
            ino: 3,
            size: 10,
            mtime_ns: 5,
            ctime_ns: 5,
        }
    }

    #[test]
    fn a_folder_of_ours_that_others_cannot_write_is_fine() {
        assert_eq!(folder_problem(&dir(0o755, 1000, 1000), &me(), false), None);
        assert_eq!(folder_problem(&dir(0o700, 1000, 1000), &me(), false), None);
    }

    #[test]
    fn a_world_writable_folder_is_never_used_even_with_allow_group_write() {
        for allow in [false, true] {
            let problem = folder_problem(&dir(0o777, 1000, 1000), &me(), allow).unwrap();
            assert!(problem.contains("world-writable"), "{problem}");
            assert!(folder_problem(&dir(0o757, 1000, 1000), &me(), allow).is_some());
        }
    }

    #[test]
    fn a_group_writable_folder_needs_the_switch() {
        let problem = folder_problem(&dir(0o775, 1000, 1000), &me(), false).unwrap();
        assert!(problem.contains("allow_group_write"), "{problem}");
        assert_eq!(folder_problem(&dir(0o775, 1000, 1000), &me(), true), None);
    }

    #[test]
    fn a_foreign_folder_is_refused_unless_it_is_shared_through_our_group() {
        assert!(folder_problem(&dir(0o755, 0, 0), &me(), false).is_some());
        assert!(folder_problem(&dir(0o755, 0, 0), &me(), true).is_some());
        assert!(folder_problem(&dir(0o755, 4242, 3000), &me(), true).is_some());
        // Owned by someone else, but the group is one of ours.
        assert_eq!(folder_problem(&dir(0o775, 4242, 2000), &me(), true), None);
        assert!(folder_problem(&dir(0o775, 4242, 2000), &me(), false).is_some());
    }

    #[test]
    fn only_a_directory_is_a_folder() {
        let mut facts = dir(0o700, 1000, 1000);
        facts.kind = Kind::Symlink;
        assert_eq!(
            folder_problem(&facts, &me(), false).as_deref(),
            Some("not a directory")
        );
    }

    #[test]
    fn a_file_must_be_a_plain_single_link_file_of_ours() {
        assert_eq!(file_problem(&file(1000, 1000, 1), &me(), 1000, false), None);
        for kind in [Kind::Symlink, Kind::Directory, Kind::Other] {
            let mut facts = file(1000, 1000, 1);
            facts.kind = kind;
            assert!(
                file_problem(&facts, &me(), 1000, false).is_some(),
                "{kind:?}"
            );
        }
        let linked = file_problem(&file(1000, 1000, 2), &me(), 1000, false).unwrap();
        assert!(linked.contains("hard links"), "{linked}");
        let foreign = file_problem(&file(4242, 1000, 1), &me(), 1000, false).unwrap();
        assert!(foreign.contains("owned by uid 4242"), "{foreign}");
    }

    #[test]
    fn a_file_of_the_shared_group_is_taken_only_with_the_switch() {
        let theirs = file(4242, 2000, 1);
        assert!(file_problem(&theirs, &me(), 2000, false).is_some());
        assert_eq!(file_problem(&theirs, &me(), 2000, true), None);
        // A different group, or a folder group the daemon is not in.
        assert!(file_problem(&file(4242, 3000, 1), &me(), 2000, true).is_some());
        assert!(file_problem(&file(4242, 3000, 1), &me(), 3000, true).is_some());
    }

    #[test]
    fn names_that_say_unfinished_are_skipped_in_any_case() {
        for name in [
            ".hidden",
            "a.part",
            "a.PART",
            "x.tmp",
            "y.crdownload",
            "z.CrDownload",
        ] {
            assert!(looks_partial(name.as_bytes()), "{name}");
        }
        for name in ["a.sh", "partial", "tmp", "a.part.sh", "sample.elf"] {
            assert!(!looks_partial(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn a_change_of_size_or_time_is_seen() {
        let a = file(1000, 1000, 1);
        let mut b = a;
        assert!(a.unchanged_since(&b));
        b.size += 1;
        assert!(!a.unchanged_since(&b));
        let mut c = a;
        c.mtime_ns += 1;
        assert!(!a.unchanged_since(&c) && a.same_file(&c));
        let mut d = a;
        d.ino += 1;
        assert!(!a.same_file(&d));
    }
}
