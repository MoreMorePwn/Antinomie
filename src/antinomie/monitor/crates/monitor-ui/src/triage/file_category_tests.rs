// SPDX-License-Identifier: GPL-3.0-only
use super::file_category::{self, Access, Category, Hit, Outcome};
use super::*;
use crate::triage::tests::{call, captured, path_call};

const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;

/// One call with its first-argument path and its arguments.
fn op(nr: u64, name: &str, ret: i64, path: Option<&str>, args: [u64; 6]) -> InvocationSummary {
    let mut call = match path {
        Some(path) => path_call(1, nr, name, ret, path),
        None => call(1, nr, name, ret),
    };
    call.entry.as_mut().unwrap().args = Some(args);
    call
}

fn open(path: &str, flags: u64, ret: i64) -> InvocationSummary {
    op(2, "open", ret, Some(path), [0, flags, 0, 0, 0, 0])
}

fn categories(files: &FdState, call: &InvocationSummary) -> Vec<Category> {
    let event = trace::representative(call).unwrap();
    file_category::classify(files, call, event)
        .into_iter()
        .map(|hit| hit.category)
        .collect()
}

fn hits(files: &FdState, call: &InvocationSummary) -> Vec<Hit> {
    let event = trace::representative(call).unwrap();
    file_category::classify(files, call, event)
}

/// What the scan does with one call: classify, then track it.
fn step(files: &mut FdState, index: &mut files::FileIndex, call: &mut InvocationSummary, id: u64) {
    call.call_id = id;
    for event in call.entry.iter_mut().chain(call.exit.iter_mut()) {
        event.call_id = id;
        event.timestamp_ns = id;
    }
    let event = trace::representative(call).unwrap().clone();
    remember_open(files, call, &event);
    let found = file_category::classify(files, call, &event);
    index.observe_with(files, call, &event, None, &found);
    sigma_events::track(files, call, &event);
}

#[test]
fn every_syscall_family_lands_in_its_category() {
    let files = FdState::default();
    let cases: Vec<(InvocationSummary, Vec<Category>)> = vec![
        (
            op(0, "read", 4, None, [3, 0, 4, 0, 0, 0]),
            vec![Category::Read],
        ),
        (
            op(17, "pread64", 4, None, [3, 0, 4, 0, 0, 0]),
            vec![Category::Read],
        ),
        (
            op(295, "preadv", 4, None, [3, 0, 4, 0, 0, 0]),
            vec![Category::Read],
        ),
        (
            op(1, "write", 4, None, [3, 0, 4, 0, 0, 0]),
            vec![Category::Written],
        ),
        (
            op(20, "writev", 4, None, [3, 0, 4, 0, 0, 0]),
            vec![Category::Written],
        ),
        (
            op(296, "pwritev", 4, None, [3, 0, 4, 0, 0, 0]),
            vec![Category::Written],
        ),
        (
            op(77, "ftruncate", 0, None, [3, 10, 0, 0, 0, 0]),
            vec![Category::Truncated],
        ),
        (
            op(76, "truncate", 0, Some("/tmp/a"), [0, 10, 0, 0, 0, 0]),
            vec![Category::Truncated],
        ),
        (
            op(285, "fallocate", 0, None, [3, 0, 0, 4096, 0, 0]),
            vec![Category::Truncated],
        ),
        (
            op(87, "unlink", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Deleted],
        ),
        (
            op(84, "rmdir", 0, Some("/tmp/d"), [0; 6]),
            vec![Category::Deleted],
        ),
        (
            op(82, "rename", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Renamed],
        ),
        (
            op(316, "renameat2", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Renamed],
        ),
        (
            op(86, "link", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Linked],
        ),
        (
            op(88, "symlink", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Linked],
        ),
        (
            op(90, "chmod", 0, Some("/tmp/a"), [0, 0o755, 0, 0, 0, 0]),
            vec![Category::Permissions],
        ),
        (
            op(91, "fchmod", 0, None, [3, 0o755, 0, 0, 0, 0]),
            vec![Category::Permissions],
        ),
        (
            op(92, "chown", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Permissions],
        ),
        (
            op(235, "utimes", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Timestamps],
        ),
        (
            op(280, "utimensat", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Timestamps],
        ),
        (
            op(188, "setxattr", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Xattrs],
        ),
        (
            op(197, "removexattr", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Xattrs],
        ),
        (
            op(40, "sendfile", 4, None, [4, 3, 0, 4, 0, 0]),
            vec![Category::Copied],
        ),
        (
            op(326, "copy_file_range", 4, None, [3, 0, 4, 0, 4, 0]),
            vec![Category::Copied],
        ),
        (
            op(275, "splice", 4, None, [3, 0, 4, 0, 4, 0]),
            vec![Category::Copied],
        ),
        (
            op(16, "ioctl", 0, None, [4, 0x4004_9409, 3, 0, 0, 0]),
            vec![Category::Copied],
        ),
        (op(16, "ioctl", 0, None, [4, 0x5401, 0, 0, 0, 0]), vec![]),
        (
            op(59, "execve", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Executed],
        ),
        (
            op(322, "execveat", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Executed],
        ),
        (
            op(4, "stat", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Probed],
        ),
        (
            op(332, "statx", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Probed],
        ),
        (
            op(21, "access", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Probed],
        ),
        (
            op(89, "readlink", 0, Some("/tmp/a"), [0; 6]),
            vec![Category::Probed],
        ),
        (
            op(217, "getdents64", 3, None, [3, 0, 0, 0, 0, 0]),
            vec![Category::DirListing],
        ),
        (
            op(254, "inotify_add_watch", 1, Some("/tmp/a"), [0; 6]),
            vec![Category::Watched],
        ),
        (
            op(73, "flock", 0, None, [3, 2, 0, 0, 0, 0]),
            vec![Category::Watched],
        ),
        (
            op(72, "fcntl", 0, None, [3, 6, 0, 0, 0, 0]),
            vec![Category::Watched],
        ),
        (op(72, "fcntl", 0, None, [3, 1, 0, 0, 0, 0]), vec![]),
        (op(39, "getpid", 1, None, [0; 6]), vec![]),
        (
            op(2, "open", 3, Some("/tmp/a"), [0, 0, 0, 0, 0, 0]),
            vec![Category::Opened],
        ),
        (
            op(83, "mkdir", 0, Some("/tmp/d"), [0; 6]),
            vec![Category::Created],
        ),
        (
            op(133, "mknod", 0, Some("/tmp/n"), [0; 6]),
            vec![Category::Created],
        ),
        (
            op(319, "memfd_create", 3, None, [0; 6]),
            vec![Category::Created],
        ),
    ];
    for (call, expected) in cases {
        let event = trace::representative(&call).unwrap();
        assert_eq!(
            categories(&files, &call),
            expected,
            "{}",
            event.syscall_name
        );
    }
}

#[test]
fn flags_decide_open_categories_and_mappings() {
    let files = FdState::default();
    // O_CREAT|O_TRUNC on an unseen path made the file: nothing was truncated.
    assert_eq!(
        categories(&files, &open("/tmp/n", O_WRONLY | O_CREAT | O_TRUNC, 3)),
        [Category::Opened, Category::Created]
    );
    // On a path seen earlier it cut an existing file.
    let mut known = FdState::default();
    let seen = open("/tmp/n", 0, 3);
    let seen_event = trace::representative(&seen).unwrap().clone();
    sigma_events::track(&mut known, &seen, &seen_event);
    assert_eq!(
        categories(&known, &open("/tmp/n", O_WRONLY | O_CREAT | O_TRUNC, 3)),
        [Category::Opened, Category::Truncated]
    );
    assert_eq!(
        categories(&known, &open("/tmp/n", O_WRONLY | O_TRUNC, 3)),
        [Category::Opened, Category::Truncated]
    );
    assert_eq!(
        categories(&files, &op(85, "creat", 3, Some("/tmp/n"), [0; 6])),
        [Category::Opened, Category::Created]
    );
    // A plain read-only open is only Opened.
    assert_eq!(
        categories(&files, &open("/tmp/n", 0, 3)),
        [Category::Opened]
    );
    // A refused O_CREAT open made nothing.
    assert_eq!(
        categories(&files, &open("/tmp/n", O_WRONLY | O_CREAT | O_TRUNC, -13)),
        [Category::Opened]
    );
    // PROT_EXEC file mapping, shared writable mapping, anonymous executable memory.
    let map = |prot: u64, flags: u64| op(9, "mmap", 0x7000, None, [0, 4096, prot, flags, 3, 0]);
    assert_eq!(categories(&files, &map(5, 2)), [Category::Mapped]);
    assert_eq!(categories(&files, &map(3, 1)), [Category::Mapped]);
    assert!(categories(&files, &map(3, 2)).is_empty());
    assert!(categories(&files, &map(7, 0x22)).is_empty());
    assert_eq!(
        categories(&files, &op(10, "mprotect", 0, None, [0, 4096, 5, 0, 0, 0])),
        [Category::Mapped]
    );
    assert!(categories(&files, &op(10, "mprotect", 0, None, [0, 4096, 3, 0, 0, 0])).is_empty());
    assert_eq!(
        categories(&files, &op(26, "msync", 0, None, [0, 4096, 4, 0, 0, 0])),
        [Category::Mapped]
    );
}

#[test]
fn created_is_inferred_only_when_the_path_was_not_seen() {
    let mut files = FdState::default();
    let new = open("/tmp/new", O_WRONLY | O_CREAT, 3);
    let created = |found: &[Hit]| {
        found
            .iter()
            .find(|hit| hit.category == Category::Created)
            .copied()
    };
    // Never seen: existence is unknown, so the label says so.
    let found = created(&hits(&files, &new)).unwrap();
    assert!(found.inferred);
    assert_eq!(found.label(), "Created (inferred)");
    // O_EXCL proves it.
    let exclusive = open("/tmp/new", O_WRONLY | O_CREAT | O_EXCL, 3);
    let found = created(&hits(&files, &exclusive)).unwrap();
    assert!(!found.inferred);
    assert_eq!(found.label(), "Created");
    // mkdir and O_TMPFILE prove it too.
    let found = hits(&files, &op(83, "mkdir", 0, Some("/tmp/d"), [0; 6]));
    assert!(!found[0].inferred);
    let tmpfile = open("/tmp", sigma_events::O_TMPFILE | O_WRONLY, 3);
    assert!(!created(&hits(&files, &tmpfile)).unwrap().inferred);
    // Once the path has been seen, O_CREAT opens an existing file.
    let event = trace::representative(&new).unwrap().clone();
    sigma_events::track(&mut files, &new, &event);
    assert!(created(&hits(&files, &new)).is_none());
    // After a delete it is new again.
    let unlink = op(87, "unlink", 0, Some("/tmp/new"), [0; 6]);
    let event = trace::representative(&unlink).unwrap().clone();
    sigma_events::track(&mut files, &unlink, &event);
    assert!(created(&hits(&files, &new)).unwrap().inferred);
    // A row for an inferred creation carries the flag and the label.
    let event = trace::representative(&new).unwrap();
    let hit = created(&hits(&files, &new)).unwrap();
    let row = file_category::category_row(&files, &new, event, hit);
    assert_eq!(row[1].text, "Created (inferred)");
    assert!(row[0]
        .values
        .iter()
        .any(|value| matches!(value, ("file.created_inferred", RowValue::Bool(true)))));
}

#[test]
fn a_file_s_lifecycle_reads_as_a_sentence() {
    let mut files = FdState::default();
    let mut index = files::FileIndex::default();
    let path = "/tmp/payload";
    let mut calls = [
        open(path, O_WRONLY | O_CREAT, 3),
        op(1, "write", 4, None, [3, 0, 4, 0, 0, 0]),
        op(1, "write", 4, None, [3, 0, 4, 0, 0, 0]),
        op(1, "write", 4, None, [3, 0, 4, 0, 0, 0]),
        op(3, "close", 0, None, [3, 0, 0, 0, 0, 0]),
        op(90, "chmod", 0, Some(path), [0, 0o755, 0, 0, 0, 0]),
        op(59, "execve", 0, Some(path), [0; 6]),
        op(87, "unlink", 0, Some(path), [0; 6]),
    ];
    for (id, call) in calls.iter_mut().enumerate() {
        step(&mut files, &mut index, call, id as u64 + 1);
    }
    let changes = index.finish();
    assert_eq!(changes.len(), 1);
    assert_eq!(
        changes[0].lifecycle_text(),
        "created (inferred) → written 3× → chmod +x → executed → deleted"
    );
    assert!(changes[0].real());
    let row = changes[0].row(None);
    assert!(row[3].text.starts_with("created (inferred)"));
    let value = |key: &str| {
        row[0]
            .values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|v| &v.1)
    };
    assert!(
        matches!(value("file.category"), Some(RowValue::List(list)) if list.contains(&"Created".to_owned()))
    );
    assert!(
        matches!(value("file.location"), Some(RowValue::List(list)) if list == &["temp".to_owned()])
    );
}

#[test]
fn chmod_steps_tell_a_new_exec_bit_from_a_repeat_and_flag_setuid() {
    let mut files = FdState::default();
    let mut index = files::FileIndex::default();
    let mut calls = [
        op(90, "chmod", 0, Some("/tmp/t"), [0, 0o644, 0, 0, 0, 0]),
        op(90, "chmod", 0, Some("/tmp/t"), [0, 0o755, 0, 0, 0, 0]),
        op(90, "chmod", 0, Some("/tmp/t"), [0, 0o700, 0, 0, 0, 0]),
        op(90, "chmod", 0, Some("/tmp/t"), [0, 0o4755, 0, 0, 0, 0]),
    ];
    for (id, call) in calls.iter_mut().enumerate() {
        step(&mut files, &mut index, call, id as u64 + 1);
    }
    assert_eq!(
        index.finish()[0].lifecycle_text(),
        "chmod 0644 → chmod +x → chmod 0755 → 0700 → chmod setuid"
    );
    assert_eq!(
        file_category::mode_flags(0o6755),
        ["setuid", "setgid", "+x"]
    );
    assert!(file_category::mode_flags(0o644).is_empty());
}

#[test]
fn failed_attempts_are_not_changes_and_stay_behind_the_toggle() {
    let mut files = FdState::default();
    let mut index = files::FileIndex::default();
    let mut calls = [
        op(87, "unlink", -2, Some("/tmp/gone"), [0; 6]),
        op(90, "chmod", -1, Some("/tmp/real"), [0, 0o755, 0, 0, 0, 0]),
        op(87, "unlink", 0, Some("/tmp/real"), [0; 6]),
    ];
    for (id, call) in calls.iter_mut().enumerate() {
        step(&mut files, &mut index, call, id as u64 + 1);
    }
    let changes = index.finish();
    assert_eq!(changes.len(), 2);
    let gone = changes
        .iter()
        .find(|change| change.path == "/tmp/gone")
        .unwrap();
    assert!(!gone.real());
    assert_eq!(
        gone.lifecycle_text(),
        "no change · 1 failed attempt not counted"
    );
    let real = changes
        .iter()
        .find(|change| change.path == "/tmp/real")
        .unwrap();
    assert!(real.real());
    // The failed chmod is not a step.
    assert_eq!(
        real.lifecycle_text(),
        "deleted · 1 failed attempt not counted"
    );
    // Hidden until asked for, by the same rule every file table uses.
    let hidden = file_visibility::FileVisibility::default();
    let shown = file_visibility::FileVisibility {
        show_failed: true,
        ..hidden
    };
    assert!(!hidden.keeps(&gone.row(None)));
    assert!(shown.keeps(&gone.row(None)));
    assert!(hidden.keeps(&real.row(None)));
}

fn sink_run(show_failed: bool) -> (normalized::Counts, FileRows, [FileRows; FILE_TABS]) {
    let mut request = ScanRequest::default();
    request.file_visibility.show_failed = show_failed;
    let cancel = Arc::new(AtomicBool::new(false));
    let mut sink = file_tabs::TabSink::new(&request, &cancel);
    let mut counts = normalized::Counts::default();
    let files = FdState::default();
    for call in [
        open("/tmp/a", 0, 3),
        open("/tmp/missing", 0, -2),
        op(87, "unlink", 0, Some("/tmp/a"), [0; 6]),
        op(87, "unlink", -2, Some("/tmp/b"), [0; 6]),
        op(90, "chmod", 0, Some("/tmp/a"), [0, 0o755, 0, 0, 0, 0]),
        op(4, "stat", 0, Some("/etc/passwd"), [0; 6]),
        op(86, "link", 0, Some("/tmp/a"), [0; 6]),
    ] {
        let event = trace::representative(&call).unwrap();
        let found = file_category::classify(&files, &call, event);
        sink.observe(&request, &mut counts, &files, &call, event, &found)
            .unwrap();
    }
    let (opened, tabs) = sink.finish().unwrap();
    (counts, opened, tabs)
}

#[test]
fn counts_badges_and_pages_leave_failed_attempts_out_unless_shown() {
    let tab = |tab: FileTab| tab.slot() - 8;
    for show in [false, true] {
        let (counts, opened, tabs) = sink_run(show);
        // Change badges never include the refused calls, whatever the toggle
        // says. Opened lists its failed opens with their result, so counts them.
        assert_eq!(counts.opened, 2);
        assert_eq!(counts.tabs[tab(FileTab::Deleted)], 1);
        assert_eq!(counts.tabs[tab(FileTab::Attributes)], 1);
        assert_eq!(counts.tabs[tab(FileTab::Probed)], 1);
        assert_eq!(counts.tabs[tab(FileTab::Other)], 1);
        assert_eq!(counts.tabs[tab(FileTab::Created)], 0);
        // The toggle is for the change categories, not Opened.
        assert_eq!(counts.failed_attempts, 1);
        assert_eq!(opened.rows.len(), 2);
        assert_eq!(opened.rows[1][6].text, "Failed (ENOENT)");
        // Rows follow the toggle.
        assert_eq!(
            tabs[tab(FileTab::Deleted)].rows.len(),
            if show { 2 } else { 1 }
        );
        assert_eq!(tabs[tab(FileTab::Attributes)].rows.len(), 1);
    }
    let (_, _, tabs) = sink_run(true);
    let failed = &tabs[tab(FileTab::Deleted)].rows[1];
    assert_eq!(failed[6].text, "Failed (ENOENT)");
    assert!(failed[0]
        .values
        .iter()
        .any(|value| matches!(value, ("file.errno", RowValue::Text(name)) if name == "ENOENT")));
}

#[test]
fn filter_fields_match_rows_and_examples_compile() {
    for tab in FileTab::ALL {
        query::assert_example_compiles(tab.example(), FILE_FIELDS);
    }
    let mut files = FdState::default();
    files.process_images.insert(
        TaskKey { pid: 1, cookie: 1 },
        TaskNode {
            root: true,
            comm: "/tmp/sample".into(),
            ..TaskNode::default()
        },
    );
    let row_for = |files: &FdState, call: &InvocationSummary, category: Category| {
        let event = trace::representative(call).unwrap();
        file_category::category_row(
            files,
            call,
            event,
            Hit {
                category,
                inferred: false,
            },
        )
    };
    let keeps = |filter: &str, row: &[Cell]| {
        let compiled = query::compile_table(filter, FILE_FIELDS);
        assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
        compiled.keep_table(&row[0].values)
    };
    let cron = row_for(
        &files,
        &op(87, "unlink", -2, Some("/etc/cron.d/job"), [0; 6]),
        Category::Deleted,
    );
    assert!(keeps("file.location == \"persistence\"", &cron));
    assert!(!keeps("file.location == \"temp\"", &cron));
    assert!(keeps("file.result == \"failed\"", &cron));
    assert!(keeps("file.errno == \"ENOENT\"", &cron));
    assert!(keeps("file.access_by == \"path\"", &cron));
    assert!(keeps("file.category == \"Deleted\"", &cron));
    let chmod = row_for(
        &files,
        &op(90, "chmod", 0, Some("/tmp/.x"), [0, 0o4755, 0, 0, 0, 0]),
        Category::Permissions,
    );
    assert!(keeps("file.mode_flags == \"setuid\"", &chmod));
    assert!(keeps("file.mode == \"4755\"", &chmod));
    assert!(keeps(
        "file.location == \"hidden\" and file.location == \"temp\"",
        &chmod
    ));
    assert_eq!(chmod[4].text, "mode 4755 (setuid, +x)");
    let own = row_for(
        &files,
        &op(87, "unlink", 0, Some("/tmp/sample"), [0; 6]),
        Category::Deleted,
    );
    assert!(keeps("file.location == \"self\"", &own));
    let fd = row_for(
        &files,
        &op(0, "write", 4, None, [9, 0, 4, 0, 0, 0]),
        Category::Written,
    );
    assert!(keeps("file.access_by == \"inherited\"", &fd));
    assert_eq!(fd[8].text, "Inherited or unknown descriptor");
}

#[test]
fn access_tells_path_descriptor_and_inherited_apart() {
    let mut files = FdState::default();
    let stat = op(4, "stat", 0, Some("/tmp/a"), [0; 6]);
    let event = trace::representative(&stat).unwrap();
    assert_eq!(file_category::access(&files, &stat, event), Access::ByPath);
    let read = op(0, "read", 4, None, [3, 0, 4, 0, 0, 0]);
    let event = trace::representative(&read).unwrap();
    assert_eq!(
        file_category::access(&files, &read, event),
        Access::Inherited
    );
    let opened = open("/tmp/a", 0, 3);
    let event = trace::representative(&opened).unwrap().clone();
    remember_open(&mut files, &opened, &event);
    let event = trace::representative(&read).unwrap();
    assert_eq!(
        file_category::access(&files, &read, event),
        Access::ByDescriptor
    );
    assert_eq!(Outcome::NoExit.tag(), "no exit");
}

#[test]
fn rename_detail_names_both_paths_and_an_overwritten_destination() {
    let mut files = FdState::default();
    let mut rename = op(82, "rename", 0, Some("/tmp/a"), [0; 6]);
    rename
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured("arg1.newname", "", b"/tmp/b\0"));
    let event = trace::representative(&rename).unwrap();
    let hit = Hit {
        category: Category::Renamed,
        inferred: false,
    };
    assert_eq!(
        file_category::detail(&files, &rename, event, hit),
        "/tmp/a → /tmp/b"
    );
    let seen = op(2, "open", 3, Some("/tmp/b"), [0; 6]);
    let seen_event = trace::representative(&seen).unwrap().clone();
    sigma_events::track(&mut files, &seen, &seen_event);
    assert_eq!(
        file_category::detail(&files, &rename, event, hit),
        "/tmp/a → /tmp/b (destination seen earlier; overwritten)"
    );
}

#[test]
fn copy_detail_names_source_and_destination() {
    let mut files = FdState::default();
    for (path, fd) in [("/etc/shadow", 3), ("/tmp/out", 4)] {
        let opened = open(path, 0, fd);
        let event = trace::representative(&opened).unwrap().clone();
        remember_open(&mut files, &opened, &event);
    }
    let copy = op(40, "sendfile", 10, None, [4, 3, 0, 10, 0, 0]);
    let event = trace::representative(&copy).unwrap();
    let hit = Hit {
        category: Category::Copied,
        inferred: false,
    };
    assert_eq!(
        file_category::detail(&files, &copy, event, hit),
        "/etc/shadow → /tmp/out"
    );
}

#[test]
fn an_index_stamped_by_an_older_format_is_rebuilt() {
    let temp = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
    super::tests::write_rwx_calls(&mut raw, 0..1);
    raw.sync_all().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let scan = scan_archive_query(
        &temp.directory,
        None,
        false,
        &cancel,
        &ScanRequest::default(),
    )
    .unwrap();
    assert!(scan
        .stamp
        .starts_with(&format!("files-v{}|", refresh::FILE_INDEX_VERSION)));
    // The same recording, unchanged: nothing to do.
    let same = ScanRequest {
        unchanged_since: Some(scan.stamp.clone()),
        ..ScanRequest::default()
    };
    assert!(matches!(
        scan_archive_query(&temp.directory, None, false, &cancel, &same),
        Err(error) if error == refresh::UNCHANGED
    ));
    // A stamp from before file indexes were versioned never matches.
    let old = scan.stamp.split_once('|').unwrap().1.to_owned();
    let stale = ScanRequest {
        unchanged_since: Some(old),
        ..ScanRequest::default()
    };
    assert!(scan_archive_query(&temp.directory, None, false, &cancel, &stale).is_ok());
}

#[test]
fn opened_and_read_draw_the_five_and_six_columns_the_cards_asked_for() {
    let full = |headers: &[&str], keep: &[usize]| -> Vec<String> {
        keep.iter()
            .map(|&index| headers[index].to_owned())
            .collect()
    };
    assert_eq!(
        full(file_category::EVENT_HEADERS, file_tabs::OPENED_COLUMNS),
        ["Time", "Path", "Process (PID / TID)", "Result", "Evidence"]
    );
    assert_eq!(
        full(file_tabs::READ_HEADERS, file_tabs::READ_COLUMNS),
        [
            "Time",
            "Path",
            "Process (PID / TID)",
            "Transferred / content",
            "Result",
            "Evidence"
        ]
    );
    // A click on a sort header sorts the full rows by the same column.
    assert_eq!(file_tabs::full_column(1, 1), 3);
    assert_eq!(file_tabs::full_column(1, 4), 9);
    assert_eq!(file_tabs::full_column(5, 5), 7);
    assert_eq!(file_tabs::full_column(8, 2), 2);
}

#[test]
fn a_failed_read_is_listed_with_its_result_while_the_toggle_is_off() {
    let visibility = file_visibility::FileVisibility::default();
    let mut row = vec![cell("t", theme::text(), true)];
    row[0].values = vec![("file.result", RowValue::Text("failed".into()))];
    assert!(!visibility.keeps(&row));
    assert!(visibility.keeps_with(&row, true));
}

fn hash_note(flags: u8) -> antinomie_monitor_core::FieldSummary {
    let mut bytes = vec![0u8; 80];
    bytes[0] = 1; // exec
    bytes[3] = flags;
    captured("lifecycle.file_hash", "antinomie.hash/1", &bytes)
}

fn executed_detail(mut call: InvocationSummary, flags: Option<u8>) -> String {
    if let Some(flags) = flags {
        let mut note = call.exit.clone().unwrap();
        note.phase = 3;
        note.fields = vec![hash_note(flags)];
        call.kernel_notes.push(note);
    }
    let event = trace::representative(&call).unwrap();
    let hit = Hit {
        category: Category::Executed,
        inferred: false,
    };
    file_category::detail(&FdState::default(), &call, event, hit)
}

#[test]
fn an_exec_of_a_script_says_its_interpreter_ran_without_naming_one() {
    let run = || op(59, "execve", 0, Some("/tmp/run.sh"), [0; 6]);
    assert_eq!(executed_detail(run(), None), "");
    assert_eq!(
        executed_detail(run(), Some(0)),
        "",
        "an image that was the file itself"
    );
    assert_eq!(
        executed_detail(run(), Some(1)),
        "script run through its interpreter, path not recorded"
    );
}
