// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::kernel_notes::{FileHash, HashKind, HashStatus};
use crate::observation::{GuestProcess, GuestProcessIdentity};

fn process(tgid: u32, cookie: u64, parent: u32, name: &str, start: u64) -> GuestProcess {
    GuestProcess {
        identity: GuestProcessIdentity {
            boot_id: "b".into(),
            task_cookie: cookie,
            tgid,
            start_boot_ns: start,
        },
        parent_tgid: parent,
        uid: 0,
        gid: 0,
        thread_count: 1,
        command: name.into(),
    }
}

fn hash(kind: HashKind, digest: u8, size: u64) -> FileHash {
    FileHash {
        kind,
        status: HashStatus::Ok,
        sha256: Some([digest; 32]),
        size,
        hashed: size,
        limit: 0,
        error: 0,
        interpreter: false,
        changed: false,
        cached: false,
        queue_us: 0,
        hash_us: 0,
        lost: 0,
        file: None,
    }
}

/// The Mirai `.e` case of the ARM evaluation (run f3c4b489), benign: before
/// the launch init, cron and sshd run; the tree is the sample (cookie 100)
/// and its bots (101, 102); cron starts pid 1050 ".e" from the copy the
/// sample wrote, and systemd starts an unrelated timesyncd.
fn mirai_like() -> (Watch, Vec<GuestProcess>, HashSet<u64>) {
    let before = [
        process(1, 1, 0, "systemd", 1),
        process(400, 40, 1, "cron", 2),
        process(410, 41, 1, "sshd", 3),
    ];
    let mut watch = Watch::with_baseline(Some(&before), true);
    watch.learn(0, &hash(HashKind::Exec, 0xaa, 4096));
    // The tree's own execs of system programs are not images of the run.
    watch.learn(7, &hash(HashKind::Exec, 0x51, 125_000));
    let mut now = before.to_vec();
    now.extend([
        process(668, 101, 1, "a", 10),
        process(669, 102, 1, "a", 11),
        process(1049, 104, 400, "cron", 20),
        process(1050, 105, 1049, ".e", 21),
        process(1060, 106, 1, "systemd-timesyn", 22),
    ]);
    let tree: HashSet<u64> = [100, 101, 102].into_iter().collect();
    (watch, now, tree)
}

#[test]
fn only_new_processes_outside_the_tree_are_candidates() {
    let (watch, now, tree) = mirai_like();
    assert!(watch.armed());
    let names: Vec<&str> = watch
        .candidates(&now, &tree)
        .iter()
        .map(|process| process.command.as_str())
        .collect();
    assert_eq!(names, ["cron", ".e", "systemd-timesyn"]);
}

#[test]
fn a_copy_is_matched_by_digest_and_size_never_by_name() {
    let (watch, ..) = mirai_like();
    assert_eq!(watch.matches(&[0xaa; 32], 4096), Some(CopyOf::Sample));
    // Same digest, other size: not the image (a forged record says nothing).
    assert_eq!(watch.matches(&[0xaa; 32], 4097), None);
    // `sh` the tree ran is not one of the run's images.
    assert_eq!(watch.matches(&[0x51; 32], 125_000), None);
    assert!(watch.size_known(4096));
    assert!(!watch.size_known(125_000));
    assert_eq!(watch.max_size(), 4096);
}

#[test]
fn written_files_count_and_the_sample_wins_over_its_written_copy() {
    let mut watch = Watch::with_baseline(Some(&[]), true);
    watch.learn(9, &hash(HashKind::Write, 0xbb, 900));
    assert_eq!(watch.matches(&[0xbb; 32], 900), Some(CopyOf::Written));
    watch.learn(0, &hash(HashKind::Exec, 0xbb, 900));
    assert_eq!(watch.matches(&[0xbb; 32], 900), Some(CopyOf::Sample));
    // A hash the guest could not finish, or of a file that changed, is not learnt.
    let mut changed = hash(HashKind::Write, 0xcc, 10);
    changed.changed = true;
    watch.learn(3, &changed);
    let mut large = hash(HashKind::Write, 0xdd, 10);
    large.status = HashStatus::TooLarge;
    watch.learn(3, &large);
    // A script's interpreter is not the launched program.
    let mut interpreter = hash(HashKind::Exec, 0xee, 10);
    interpreter.interpreter = true;
    watch.learn(0, &interpreter);
    assert!(!watch.size_known(10));
}

#[test]
fn a_copy_of_a_program_the_tree_ran_is_not_the_runs_own() {
    // BusyBox: `cp` is busybox, and it copies busybox: the copy is not the run's.
    let mut watch = Watch::with_baseline(Some(&[]), true);
    watch.learn(4, &hash(HashKind::Exec, 0x33, 1_000_000));
    watch.learn(5, &hash(HashKind::Write, 0x33, 1_000_000));
    assert_eq!(watch.matches(&[0x33; 32], 1_000_000), None);
    // A dropped file the tree runs afterwards stays the run's.
    watch.learn(6, &hash(HashKind::Write, 0x44, 50));
    watch.learn(7, &hash(HashKind::Exec, 0x44, 50));
    assert_eq!(watch.matches(&[0x44; 32], 50), Some(CopyOf::Written));
}

#[test]
fn a_launched_program_that_is_not_the_sample_is_not_learnt() {
    // A desktop run starts /bin/sh; a library runs under a loader.
    let mut watch = Watch::with_baseline(Some(&[]), false);
    watch.learn(0, &hash(HashKind::Exec, 0x55, 125_000));
    assert!(!watch.armed());
    assert_eq!(watch.matches(&[0x55; 32], 125_000), None);
}

#[test]
fn a_watch_without_a_baseline_or_an_image_follows_nothing() {
    let (_, now, tree) = mirai_like();
    let mut blind = Watch::with_baseline(None, true);
    blind.learn(0, &hash(HashKind::Exec, 0xaa, 4096));
    assert!(!blind.armed());
    assert!(blind.candidates(&now, &tree).is_empty());
    assert!(!Watch::with_baseline(Some(&[]), true).armed());
}

#[test]
fn looked_at_processes_are_not_read_again_except_unreadable_ones_a_few_times() {
    let (mut watch, now, tree) = mirai_like();
    let cron = now
        .iter()
        .find(|process| process.identity.tgid == 1049)
        .unwrap();
    let timesync = now
        .iter()
        .find(|process| process.identity.tgid == 1060)
        .unwrap();
    watch.note(cron, Looked::NotACopy);
    for _ in 0..2 {
        watch.note(timesync, Looked::Unreadable(0));
    }
    let left: Vec<u32> = watch
        .candidates(&now, &tree)
        .iter()
        .map(|process| process.identity.tgid)
        .collect();
    assert_eq!(left, [1050, 1060]);
    watch.note(timesync, Looked::Unreadable(0));
    let left: Vec<u32> = watch
        .candidates(&now, &tree)
        .iter()
        .map(|process| process.identity.tgid)
        .collect();
    assert_eq!(left, [1050]);
}

#[test]
fn a_found_copy_names_its_starter_and_ends_when_it_is_gone() {
    let (mut watch, now, _) = mirai_like();
    let copy = now
        .iter()
        .find(|process| process.identity.tgid == 1050)
        .unwrap();
    let mut copies = PersistedCopies::default();
    found(
        &mut copies,
        copy,
        Some("cron".into()),
        (CopyOf::Sample, &[0xaa; 32], 4096),
        1_000,
    );
    watch.note(copy, Looked::Copy);
    let note = found_note(&copies.copies[0]);
    assert!(note.starts_with("pid 1050 \".e\" runs a copy of the sample outside the recorded tree (started by pid 1049 \"cron\", uid 0, SHA-256 aaaa"), "{note}");
    // Its fork under the same name is its child, not read again.
    let mut later = now.clone();
    later.push(process(1051, 107, 1050, ".e", 30));
    assert_eq!(refresh(&mut copies, &mut watch, &later, 2_000), 1);
    assert_eq!(copies.copies[0].children, 1);
    assert_eq!(copies.copies[0].last_seen_ms, 2_000);
    assert!(hold_end(&copies, Duration::from_secs(5)).is_none());
    assert!(hold_note(&copies).contains("pid 1050 \".e\" still ran outside it"));
    // Gone, or the pid now belongs to another process: ended.
    let mut reused = now.clone();
    reused.retain(|process| process.identity.tgid != 1050);
    reused.push(process(1050, 900, 1, "bash", 99));
    refresh(&mut copies, &mut watch, &reused, 3_000);
    assert!(copies.copies[0].ended);
    assert_eq!(copies.copies[0].last_seen_ms, 2_000);
    assert_eq!(
        hold_end(&copies, Duration::from_secs(5)),
        Some("every copy outside the tree exited")
    );
}

#[test]
fn the_hold_ends_at_its_limit_while_a_copy_still_runs() {
    let (_, now, _) = mirai_like();
    let copy = now
        .iter()
        .find(|process| process.identity.tgid == 1050)
        .unwrap();
    let mut copies = PersistedCopies::default();
    found(&mut copies, copy, None, (CopyOf::Written, &[1; 32], 8), 0);
    assert_eq!(copies.copies[0].started_by(), "started by pid 1049");
    assert!(hold_end(&copies, HOLD_MAX).unwrap().contains("hold limit"));
}

#[test]
fn copies_past_the_limit_are_counted_and_the_record_round_trips() {
    let (_, now, _) = mirai_like();
    let copy = now
        .iter()
        .find(|process| process.identity.tgid == 1050)
        .unwrap();
    let mut copies = PersistedCopies::default();
    for _ in 0..COPIES_MAX + 2 {
        found(&mut copies, copy, None, (CopyOf::Sample, &[2; 32], 8), 0);
    }
    assert_eq!(copies.copies.len(), COPIES_MAX);
    assert_eq!(copies.more, 2);
    copies.holding = true;
    let json = serde_json::to_string(&copies).unwrap();
    let back: PersistedCopies = serde_json::from_str(&json).unwrap();
    assert_eq!(back, copies);
    // A record from before the field existed reads as empty.
    let empty: PersistedCopies = serde_json::from_str("{}").unwrap();
    assert_eq!(empty, PersistedCopies::default());
}
