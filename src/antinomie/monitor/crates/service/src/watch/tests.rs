// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the watch folders (T9 cases of card P4-2): real folders in a
//! temporary directory, the daemon's side faked, the clock moved by hand.

use super::{
    Admission, Admit, Defer, WatchEnv, Watcher,
    safety::Identity,
    scan::{RATE_WINDOW_MS, STABLE_MS},
};
use crate::config::service::{DeleteAfter, OnDuplicate, Watch};
use std::{
    fs,
    io::Read,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::Mutex,
};

type Answer = Box<dyn FnMut(&str) -> Result<Admission, Defer> + Send>;

struct Fake {
    presets: Vec<String>,
    room: Mutex<bool>,
    held: Mutex<bool>,
    answer: Mutex<Answer>,
    admitted: Mutex<Vec<Taken>>,
    alerts: Mutex<Vec<(String, String)>>,
    logs: Mutex<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Taken {
    shown: String,
    file_name: String,
    bytes: Vec<u8>,
    preset: String,
    label: String,
    on_duplicate: Option<OnDuplicate>,
}

impl Fake {
    fn new() -> Self {
        let counter = Mutex::new(0u32);
        Self {
            presets: vec!["standard".into(), "strict".into()],
            room: Mutex::new(true),
            held: Mutex::new(false),
            answer: Mutex::new(Box::new(move |_| {
                let mut n = counter.lock().unwrap();
                *n += 1;
                Ok(Admission::Submitted {
                    job: format!("j_{n}"),
                })
            })),
            admitted: Mutex::new(Vec::new()),
            alerts: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
        }
    }

    fn answer_with(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }

    fn taken(&self) -> Vec<Taken> {
        self.admitted.lock().unwrap().clone()
    }

    fn names(&self) -> Vec<String> {
        self.taken().into_iter().map(|t| t.shown).collect()
    }

    fn alert_codes(&self) -> Vec<String> {
        self.alerts
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.0.clone())
            .collect()
    }
}

impl WatchEnv for Fake {
    fn preset_exists(&self, name: &str) -> bool {
        self.presets.iter().any(|p| p == name)
    }
    fn queue_has_room(&self) -> bool {
        *self.room.lock().unwrap()
    }
    fn intake_held(&self) -> bool {
        *self.held.lock().unwrap()
    }
    fn admit(&self, mut request: Admit) -> Result<Admission, Defer> {
        let mut bytes = Vec::new();
        request.file.read_to_end(&mut bytes).unwrap();
        let answer = (self.answer.lock().unwrap())(&request.shown);
        if matches!(answer, Ok(Admission::Submitted { .. })) {
            self.admitted.lock().unwrap().push(Taken {
                shown: request.shown,
                file_name: request.file_name,
                bytes,
                preset: request.preset,
                label: request.folder_label,
                on_duplicate: request.on_duplicate,
            });
        }
        answer
    }
    fn alert(&self, code: &str, text: &str) {
        self.alerts
            .lock()
            .unwrap()
            .push((code.to_owned(), text.to_owned()));
    }
    fn log(&self, line: &str) {
        self.logs.lock().unwrap().push(line.to_owned());
    }
}

struct Rig {
    root: PathBuf,
    inbox: PathBuf,
    folder: PathBuf,
    outside: PathBuf,
    env: Fake,
    watcher: Watcher,
    cfg: Watch,
}

fn unique(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-watch-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn private(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

impl Rig {
    fn new(name: &str) -> Self {
        Self::with(name, |_| {})
    }

    fn with(name: &str, tune: impl FnOnce(&mut Watch)) -> Self {
        let root = unique(name);
        let inbox = root.join("inbox");
        let folder = root.join("drop");
        let outside = root.join("outside");
        private(&inbox);
        private(&folder);
        private(&outside);
        let mut cfg = Watch {
            path: folder.clone(),
            preset: "standard".into(),
            recursive: false,
            delete_after: DeleteAfter::Move,
            on_duplicate: None,
            preset_by_dir: false,
            allow_group_write: false,
            watch_rate: 10,
            permissions: Vec::new(),
            policy: None,
            policy_by_dir: None,
        };
        tune(&mut cfg);
        let mut watcher = Watcher::new(&inbox);
        watcher.configure(std::slice::from_ref(&cfg));
        Self {
            root,
            inbox,
            folder,
            outside,
            env: Fake::new(),
            watcher,
            cfg,
        }
    }

    fn scan(&mut self, now_ms: u64) {
        self.watcher.scan_all(&self.env, now_ms);
    }

    /// Scans at 0, 2 s and 4 s: a file there from the start is taken at 4 s.
    fn settle(&mut self) {
        for t in [0, 2_000, 4_000] {
            self.scan(t);
        }
    }

    fn put(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.folder.join(name);
        if let Some(parent) = path.parent()
            && parent != self.folder
        {
            fs::create_dir_all(parent).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(&path, bytes).unwrap();
        path
    }

    fn status(&self) -> super::scan::FolderStatus {
        self.watcher.statuses().remove(0)
    }

    fn processed(&self) -> Vec<String> {
        list(&self.inbox.join("processed"))
    }

    fn rejected(&self) -> Vec<String> {
        list(&self.inbox.join("rejected"))
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn list(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn a_file_is_taken_once_its_size_has_been_steady_for_three_seconds() {
    let mut rig = Rig::new("stable");
    rig.put("a.sh", b"echo hi\n");
    rig.scan(0);
    rig.scan(2_000);
    assert!(rig.env.taken().is_empty(), "2 s is not enough");
    rig.scan(STABLE_MS);
    let taken = rig.env.taken();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].bytes, b"echo hi\n");
    assert_eq!(taken[0].shown, "a.sh");
    assert_eq!(taken[0].preset, "standard");
    assert_eq!(taken[0].label, "drop");
    assert_eq!(rig.status().taken, 1);
}

#[test]
fn a_file_that_grows_is_not_taken_until_it_stops() {
    let mut rig = Rig::new("growing");
    let path = rig.put("big.bin", b"first");
    rig.scan(0);
    rig.scan(2_000);
    fs::write(&path, b"first and second").unwrap();
    rig.scan(4_000);
    rig.scan(6_000);
    assert!(rig.env.taken().is_empty(), "it changed at 4 s");
    rig.scan(7_000);
    assert_eq!(rig.env.taken().len(), 1);
    assert_eq!(rig.env.taken()[0].bytes, b"first and second");
}

#[test]
fn files_present_at_the_start_are_taken_in_name_order() {
    let mut rig = Rig::new("order");
    for name in ["c.sh", "a.sh", "b.sh"] {
        rig.put(name, name.as_bytes());
    }
    rig.settle();
    assert_eq!(rig.env.names(), ["a.sh", "b.sh", "c.sh"]);
}

#[test]
fn unfinished_names_are_never_taken() {
    let mut rig = Rig::new("partial");
    for name in ["a.part", "b.tmp", "c.crdownload", ".hidden", "D.PART"] {
        rig.put(name, b"x");
    }
    rig.settle();
    rig.scan(60_000);
    assert!(rig.env.taken().is_empty());
    assert_eq!(list(&rig.folder).len(), 5, "left where they are");
}

#[test]
fn a_symlink_to_a_file_outside_is_refused_and_never_opened() {
    let mut rig = Rig::new("symlink");
    let secret = rig.outside.join("shadow");
    fs::write(&secret, b"root:x:0:0").unwrap();
    symlink(&secret, rig.folder.join("link.sh")).unwrap();
    rig.settle();
    rig.scan(60_000);
    assert!(rig.env.taken().is_empty());
    assert!(
        fs::symlink_metadata(rig.folder.join("link.sh"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&secret).unwrap(), b"root:x:0:0");
    let refused = rig.status().refused;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].name, "link.sh");
    assert!(refused[0].reason.contains("symbolic link"));
}

#[test]
fn a_symlinked_folder_is_not_followed_even_when_recursive() {
    let mut rig = Rig::with("dirlink", |c| c.recursive = true);
    fs::write(rig.outside.join("loot.sh"), b"outside").unwrap();
    symlink(&rig.outside, rig.folder.join("sub")).unwrap();
    rig.settle();
    rig.scan(60_000);
    assert!(rig.env.taken().is_empty(), "{:?}", rig.env.names());
}

#[test]
fn a_watch_path_that_is_itself_a_symlink_is_not_used() {
    let mut rig = Rig::new("rootlink");
    fs::write(rig.outside.join("loot.sh"), b"outside").unwrap();
    let real = rig.root.join("real");
    private(&real);
    fs::write(real.join("a.sh"), b"a").unwrap();
    let link = rig.root.join("link");
    symlink(&real, &link).unwrap();
    rig.cfg.path = link;
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    rig.settle();
    assert!(rig.env.taken().is_empty());
    assert_eq!(rig.status().state, "error");
}

#[test]
fn a_file_with_a_second_hard_link_is_refused() {
    let mut rig = Rig::new("hardlink");
    let original = rig.outside.join("data");
    fs::write(&original, b"shared").unwrap();
    fs::hard_link(&original, rig.folder.join("linked.sh")).unwrap();
    rig.put("plain.sh", b"plain");
    rig.settle();
    assert_eq!(rig.env.names(), ["plain.sh"]);
    let refused = rig.status().refused;
    assert!(refused[0].reason.contains("hard links"), "{refused:?}");
    assert!(rig.folder.join("linked.sh").exists());
}

#[test]
fn a_fifo_is_refused_without_being_opened() {
    let mut rig = Rig::new("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        rig.folder.join("pipe.sh"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    rig.settle();
    assert!(rig.env.taken().is_empty());
    assert!(
        rig.status().refused[0]
            .reason
            .contains("not a regular file")
    );
}

#[test]
fn a_file_of_another_user_is_refused() {
    let me = Identity::current();
    let mut rig = Rig::new("foreign");
    rig.watcher = Watcher::new(&rig.inbox).with_identity(Identity {
        uid: me.uid + 1,
        gid: me.gid + 1,
        groups: vec![me.gid + 1],
    });
    rig.put("a.sh", b"a");
    // The folder is ours, so as another user it is refused as a whole.
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    rig.settle();
    assert!(rig.env.taken().is_empty());
    assert_eq!(rig.status().state, "refused");
    assert!(rig.status().detail.unwrap().contains("owned by uid"));
}

#[test]
fn a_foreign_file_in_our_folder_is_refused_with_the_owner_named() {
    let mut rig = Rig::new("foreignfile");
    // Pretend the daemon runs as a user who owns the folder but not the file:
    // the folder's owner is checked against the identity, so make the
    // identity match the folder through the group switch instead.
    let me = Identity::current();
    rig.cfg.allow_group_write = true;
    rig.watcher = Watcher::new(&rig.inbox).with_identity(Identity {
        uid: me.uid + 5,
        gid: me.gid,
        groups: vec![me.gid],
    });
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    rig.put("theirs.sh", b"x");
    rig.settle();
    // The folder passes (its group is the daemon's), and the file is in the
    // folder's group: it is taken only because of allow_group_write.
    assert_eq!(rig.env.names(), ["theirs.sh"]);
    // Without the switch the folder itself is refused.
    let mut rig2 = Rig::new("foreignfile2");
    rig2.watcher = Watcher::new(&rig2.inbox).with_identity(Identity {
        uid: me.uid + 5,
        gid: me.gid,
        groups: vec![me.gid],
    });
    rig2.watcher.configure(std::slice::from_ref(&rig2.cfg));
    rig2.put("theirs.sh", b"x");
    rig2.settle();
    assert!(rig2.env.taken().is_empty());
}

#[test]
fn a_world_writable_folder_is_refused_once_with_an_alert() {
    let mut rig = Rig::new("worldwrite");
    fs::set_permissions(&rig.folder, fs::Permissions::from_mode(0o777)).unwrap();
    rig.put("a.sh", b"a");
    rig.settle();
    rig.scan(10_000);
    assert!(rig.env.taken().is_empty());
    assert_eq!(rig.status().state, "refused");
    assert_eq!(rig.env.alert_codes(), ["watch_folder_refused"], "one alert");
    // Not even the group switch lets a world-writable folder in.
    rig.cfg.allow_group_write = true;
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    rig.scan(20_000);
    assert_eq!(rig.status().state, "refused");
    // Fixing the mode brings it back.
    fs::set_permissions(&rig.folder, fs::Permissions::from_mode(0o700)).unwrap();
    rig.scan(30_000);
    rig.scan(34_000);
    assert_eq!(rig.env.names(), ["a.sh"]);
}

#[test]
fn a_group_writable_folder_needs_allow_group_write() {
    let mut rig = Rig::new("groupwrite");
    fs::set_permissions(&rig.folder, fs::Permissions::from_mode(0o770)).unwrap();
    rig.put("a.sh", b"a");
    rig.settle();
    assert!(rig.env.taken().is_empty());
    assert!(rig.status().detail.unwrap().contains("allow_group_write"));
    rig.cfg.allow_group_write = true;
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    rig.scan(10_000);
    rig.scan(14_000);
    assert_eq!(rig.env.names(), ["a.sh"]);
}

#[test]
fn a_flood_pauses_the_folder_for_a_minute_and_raises_one_alert() {
    let mut rig = Rig::with("flood", |c| c.watch_rate = 2);
    for name in ["a.sh", "b.sh", "c.sh", "d.sh"] {
        rig.put(name, name.as_bytes());
    }
    rig.settle();
    assert_eq!(rig.env.names(), ["a.sh", "b.sh"]);
    assert_eq!(rig.env.alert_codes(), ["watch_flood"]);
    assert_eq!(rig.status().state, "paused");
    assert_eq!(rig.status().pending, 2);
    rig.scan(10_000);
    rig.scan(40_000);
    assert_eq!(rig.env.names().len(), 2, "still paused");
    rig.scan(4_000 + RATE_WINDOW_MS + 1);
    assert_eq!(
        rig.env.names(),
        ["a.sh", "b.sh", "c.sh", "d.sh"].map(String::from)[..4]
    );
    assert_eq!(
        rig.env.alert_codes(),
        ["watch_flood"],
        "the second two filled the rate again, and the next pause raises its own alert later"
    );
}

#[test]
fn processed_files_move_out_with_a_safe_name() {
    let mut rig = Rig::new("processed");
    rig.put("we ird;name$(x).sh", b"a");
    rig.settle();
    assert!(!rig.folder.join("we ird;name$(x).sh").exists());
    let processed = rig.processed();
    assert_eq!(processed.len(), 1);
    assert!(
        processed[0].ends_with("-we_ird_name__x_.sh"),
        "{processed:?}"
    );
    assert!(
        processed[0]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    );
}

#[test]
fn delete_after_delete_removes_the_file() {
    let mut rig = Rig::with("delete", |c| c.delete_after = DeleteAfter::Delete);
    rig.put("a.sh", b"a");
    rig.settle();
    assert_eq!(rig.env.names(), ["a.sh"]);
    assert!(list(&rig.folder).is_empty());
    assert!(rig.processed().is_empty());
}

#[test]
fn kept_files_are_not_taken_again_not_even_after_a_restart() {
    let mut rig = Rig::with("keep", |c| c.delete_after = DeleteAfter::Keep);
    let path = rig.put("a.sh", b"a");
    rig.settle();
    rig.scan(30_000);
    assert_eq!(rig.env.names(), ["a.sh"]);
    assert!(path.exists());
    // A restart: a new watcher reads the record.
    let mut again = Watcher::new(&rig.inbox);
    again.configure(std::slice::from_ref(&rig.cfg));
    for t in [100_000, 102_000, 104_000, 106_000] {
        again.scan_all(&rig.env, t);
    }
    assert_eq!(rig.env.names().len(), 1);
    // A rewritten file is a new file.
    fs::write(&path, b"changed content").unwrap();
    for t in [200_000, 202_000, 204_000, 206_000] {
        again.scan_all(&rig.env, t);
    }
    assert_eq!(rig.env.names().len(), 2);
}

#[test]
fn a_rejected_file_goes_to_rejected_with_its_reason_and_is_not_retried() {
    let mut rig = Rig::new("rejected");
    rig.env.answer_with(Box::new(|_| {
        Ok(Admission::Rejected {
            code: "sample_type_denied".into(),
            message: "preset default does not accept type exe\nsecond line".into(),
        })
    }));
    rig.put("bad.exe", b"MZ");
    rig.settle();
    rig.scan(60_000);
    assert!(list(&rig.folder).is_empty());
    let rejected = rig.rejected();
    assert_eq!(rejected.len(), 2, "{rejected:?}");
    let reason = rejected.iter().find(|n| n.ends_with(".reason")).unwrap();
    let text = fs::read_to_string(rig.inbox.join("rejected").join(reason)).unwrap();
    assert!(
        text.starts_with("sample_type_denied: preset default"),
        "{text}"
    );
    assert_eq!(text.lines().count(), 1, "control characters are removed");
    assert_eq!(rig.status().rejected, 1);
    assert!(rig.env.taken().is_empty());
}

#[test]
fn a_file_the_queue_could_not_take_stays_and_is_tried_after_a_pause() {
    let mut rig = Rig::new("defer");
    let mut first = true;
    rig.env.answer_with(Box::new(move |_| {
        if std::mem::take(&mut first) {
            Err(Defer("the queue is full".into()))
        } else {
            Ok(Admission::Submitted { job: "j_1".into() })
        }
    }));
    rig.put("a.sh", b"a");
    rig.settle();
    assert!(rig.env.taken().is_empty());
    assert!(rig.folder.join("a.sh").exists(), "untouched");
    assert_eq!(rig.status().state, "error");
    rig.scan(30_000);
    assert!(rig.env.taken().is_empty(), "paused for a minute");
    rig.scan(4_000 + RATE_WINDOW_MS);
    assert_eq!(rig.env.names(), ["a.sh"]);
}

#[test]
fn a_full_queue_or_a_low_disk_holds_the_files() {
    let mut rig = Rig::new("held");
    rig.put("a.sh", b"a");
    *rig.env.room.lock().unwrap() = false;
    rig.settle();
    assert!(rig.env.taken().is_empty());
    assert_eq!(rig.status().state, "held");
    *rig.env.room.lock().unwrap() = true;
    *rig.env.held.lock().unwrap() = true;
    rig.scan(10_000);
    assert!(rig.env.taken().is_empty());
    *rig.env.held.lock().unwrap() = false;
    rig.scan(12_000);
    assert_eq!(rig.env.names(), ["a.sh"]);
}

#[test]
fn a_folder_named_after_a_preset_picks_that_preset_and_other_names_are_ignored() {
    let mut rig = Rig::with("bydir", |c| c.preset_by_dir = true);
    rig.put("root.sh", b"r");
    rig.put("strict/s.sh", b"s");
    rig.put("standard/d.sh", b"d");
    rig.put("nonsense/x.sh", b"x");
    rig.put("strict/deeper/y.sh", b"y");
    rig.settle();
    let mut got: Vec<(String, String)> = rig
        .env
        .taken()
        .into_iter()
        .map(|t| (t.shown, t.preset))
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("root.sh".to_owned(), "standard".to_owned()),
            ("standard/d.sh".to_owned(), "standard".to_owned()),
            ("strict/s.sh".to_owned(), "strict".to_owned()),
        ]
    );
    assert!(rig.folder.join("nonsense/x.sh").exists());
    assert!(
        rig.folder.join("strict/deeper/y.sh").exists(),
        "not recursive"
    );
}

#[test]
fn recursion_is_off_unless_asked_and_names_are_folder_relative() {
    let mut flat = Rig::new("flat");
    flat.put("sub/a.sh", b"a");
    flat.settle();
    assert!(flat.env.taken().is_empty());

    let mut deep = Rig::with("deep", |c| c.recursive = true);
    deep.put("sub/inner/a.sh", b"a");
    deep.settle();
    let taken = deep.env.taken();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].shown, "sub/inner/a.sh");
    assert_eq!(taken[0].file_name, "a.sh");
}

#[test]
fn the_duplicate_rule_of_the_folder_is_passed_on() {
    let mut rig = Rig::with("dup", |c| c.on_duplicate = Some(OnDuplicate::Reject));
    rig.put("a.sh", b"a");
    rig.settle();
    assert_eq!(rig.env.taken()[0].on_duplicate, Some(OnDuplicate::Reject));
}

#[test]
fn the_inboxs_own_folders_are_never_walked_when_the_inbox_is_watched() {
    let mut rig = Rig::new("selfwatch");
    rig.cfg.path = rig.inbox.clone();
    rig.cfg.recursive = true;
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    for sub in ["processed", "rejected", "uploads"] {
        private(&rig.inbox.join(sub));
        fs::write(rig.inbox.join(sub).join("old.sh"), b"old").unwrap();
    }
    fs::write(rig.inbox.join("new.sh"), b"new").unwrap();
    rig.settle();
    assert_eq!(rig.env.names(), ["new.sh"]);
    // The record of kept files is a hidden file and is never taken either.
    rig.scan(60_000);
    assert_eq!(rig.env.names(), ["new.sh"]);
}

#[test]
fn a_file_replaced_between_the_look_and_the_open_is_not_taken() {
    let mut rig = Rig::new("swap");
    let path = rig.put("a.sh", b"first");
    rig.scan(0);
    rig.scan(2_000);
    // Replace the file by another one of the same size before it is taken.
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"other").unwrap();
    rig.scan(4_000);
    assert!(rig.env.taken().is_empty(), "a different file starts again");
    rig.scan(6_000);
    rig.scan(8_000);
    assert_eq!(rig.env.taken()[0].bytes, b"other");
}

#[test]
fn a_config_reload_keeps_the_folders_state_and_drops_removed_folders() {
    let mut rig = Rig::new("reload");
    rig.put("a.sh", b"a");
    rig.scan(0);
    rig.cfg.watch_rate = 5;
    rig.watcher.configure(std::slice::from_ref(&rig.cfg));
    rig.scan(4_000);
    assert_eq!(
        rig.env.names(),
        ["a.sh"],
        "the first sighting survived the reload"
    );
    rig.watcher.configure(&[]);
    assert!(rig.watcher.statuses().is_empty());
}

#[test]
fn a_missing_preset_or_folder_is_an_error_state_not_a_crash() {
    let mut rig = Rig::with("nopreset", |c| c.preset = "gone".into());
    rig.put("a.sh", b"a");
    rig.settle();
    assert_eq!(rig.status().state, "error");
    assert!(rig.status().detail.unwrap().contains("gone"));
    let mut rig = Rig::new("nofolder");
    fs::remove_dir_all(&rig.folder).unwrap();
    rig.scan(0);
    assert_eq!(rig.status().state, "error");
}
