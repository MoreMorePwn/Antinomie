// SPDX-License-Identifier: GPL-3.0-only
//! The daemon side of watch folders, retention and delivery (cards P4-2 to
//! P4-4): a watched file becomes a job of the policy's actor, the operations
//! `watch.list` and `watch.scan` and their scopes.

use super::{
    tests::{SCRIPT, call, me, socket_ctx, submit_upload, svc},
    watch_env::{ServiceEnv, watch_caller},
};
use crate::{
    api::{
        error::ErrorCode,
        job::Outcome,
        ops::{Caller, Scope},
    },
    config::service::{DeleteAfter, OnDuplicate, Watch},
    server::{CallContext, Handler, Transport},
    watch::Watcher,
};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn drop_folder(svc: &super::tests::Svc, name: &str) -> (PathBuf, Watch) {
    let folder = svc.dir.join(name);
    fs::create_dir_all(&folder).unwrap();
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
    let watch = Watch {
        path: folder.clone(),
        policy: "default".into(),
        recursive: false,
        delete_after: DeleteAfter::Move,
        on_duplicate: None,
        policy_by_dir: false,
        allow_group_write: false,
        watch_rate: 10,
    };
    (folder, watch)
}

fn settle(watcher: &mut Watcher, env: &ServiceEnv) {
    for t in [0, 2_000, 4_000] {
        watcher.scan_all(env, t);
    }
}

fn names(dir: &std::path::Path) -> Vec<String> {
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
fn a_watched_file_becomes_a_queued_job_of_the_policys_actor() {
    let svc = svc("watch-job", |_| {});
    let (folder, watch) = drop_folder(&svc, "drop-here");
    fs::write(folder.join("hello.sh"), SCRIPT).unwrap();
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    settle(&mut watcher, &env);

    let listed = call(&svc, "job.list", json!({})).unwrap();
    let jobs = listed["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1, "{listed}");
    let job = &jobs[0];
    assert_eq!(job["state"], "queued");
    assert_eq!(job["client_id"], "auto:policy-default");
    assert_eq!(job["labels"]["watch"], "drop-here");
    assert_eq!(job["sample"]["type"], "sh");
    assert_eq!(job["sample"]["name"], "hello.sh");
    // The file moved out of the folder to processed/.
    assert!(names(&folder).is_empty());
    let processed = names(&svc.dir.join("data").join("inbox").join("processed"));
    assert_eq!(processed.len(), 1);
    assert!(processed[0].ends_with("-hello.sh"));
    // The library knows it was brought by the folder's actor, by name only.
    let library = antinomie_monitor_core::samples::Library::open(&svc.dir.join("data")).unwrap();
    let sha = job["sample"]["sha256"].as_str().unwrap();
    let events = library.events(sha).unwrap();
    let added = events.first().expect("an Added entry");
    assert_eq!(added.by, "auto:policy-default");
    let text = format!("{:?}", added.event);
    assert!(
        text.contains("Automation") && !text.contains("drop-here"),
        "{text}"
    );
}

#[test]
fn a_file_the_policy_does_not_accept_is_rejected_and_never_reaches_the_library() {
    let svc = svc("watch-reject", |p| {
        p.sample.accept_types = vec!["elf".into()]
    });
    let (folder, watch) = drop_folder(&svc, "drop");
    fs::write(folder.join("script.sh"), SCRIPT).unwrap();
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    settle(&mut watcher, &env);

    let rejected = names(&svc.dir.join("data").join("inbox").join("rejected"));
    assert_eq!(rejected.len(), 2, "{rejected:?}");
    let reason = rejected.iter().find(|n| n.ends_with(".reason")).unwrap();
    let text = fs::read_to_string(svc.dir.join("data/inbox/rejected").join(reason)).unwrap();
    assert!(text.starts_with("sample_type_denied:"), "{text}");
    assert_eq!(
        call(&svc, "job.list", json!({})).unwrap()["jobs"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let library = antinomie_monitor_core::samples::Library::open(&svc.dir.join("data")).unwrap();
    assert!(
        library.list().unwrap().is_empty(),
        "a denied sample is not archived"
    );
}

#[test]
fn a_duplicate_the_folder_denies_is_rejected_with_the_failure_code() {
    let svc = svc("watch-dup", |_| {});
    let (folder, mut watch) = drop_folder(&svc, "drop");
    watch.on_duplicate = Some(OnDuplicate::Reject);
    // The first copy becomes a job and finishes.
    let first = submit_upload(&svc);
    let started = svc
        .service
        .store
        .claim_next(&crate::api::ids::LaneId::new(1), &mut |_| {
            crate::store::Eligibility::Ready
        })
        .unwrap()
        .unwrap();
    assert_eq!(started.id, first.id);
    svc.service
        .store
        .finish(&first.id, Outcome::Succeeded, None)
        .unwrap();
    fs::write(folder.join("again.sh"), SCRIPT).unwrap();
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    settle(&mut watcher, &env);
    let rejected = names(&svc.dir.join("data/inbox/rejected"));
    let reason = rejected
        .iter()
        .find(|n| n.ends_with(".reason"))
        .expect("moved");
    let text = fs::read_to_string(svc.dir.join("data/inbox/rejected").join(reason)).unwrap();
    assert!(text.starts_with("duplicate_denied:"), "{text}");
}

#[test]
fn a_policy_that_does_not_allow_the_actor_leaves_the_file_where_it_is() {
    let svc = svc("watch-access", |p| {
        p.access.clients = vec!["local:*".into()]
    });
    let (folder, watch) = drop_folder(&svc, "drop");
    fs::write(folder.join("a.sh"), SCRIPT).unwrap();
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    settle(&mut watcher, &env);
    assert_eq!(names(&folder), ["a.sh"]);
    let statuses = watcher.statuses();
    assert_eq!(statuses[0].state, "error");
    assert!(
        statuses[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("access.clients")
    );
}

#[test]
fn a_full_queue_holds_the_watched_files() {
    let svc = svc("watch-full", |_| {});
    svc.service.config.write().unwrap().queue.max_queued = 1;
    submit_upload(&svc);
    let (folder, watch) = drop_folder(&svc, "drop");
    fs::write(folder.join("a.sh"), b"#!/bin/sh\necho other\n").unwrap();
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    settle(&mut watcher, &env);
    assert_eq!(names(&folder), ["a.sh"]);
    assert_eq!(watcher.statuses()[0].state, "held");
}

#[test]
fn the_watch_caller_may_only_submit_to_its_own_policy() {
    let caller = watch_caller("strict");
    assert_eq!(caller.client_id, "auto:policy-strict");
    assert_eq!(caller.scopes, [Scope::Submit]);
    assert_eq!(caller.policies, ["strict"]);
}

#[test]
fn watch_operations_check_their_scopes() {
    let svc = svc("ops-scopes", |_| {});
    let reader = CallContext {
        caller: Caller {
            client_id: "local:1".into(),
            scopes: vec![Scope::Read],
            policies: vec![],
        },
        cancel: Default::default(),
        transport: Transport::Socket,
    };
    assert_eq!(
        svc.service
            .call("watch.scan", json!({}), &reader)
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert!(svc.service.call("watch.list", json!({}), &reader).is_ok());
    let unknown = svc
        .service
        .call("watch.bogus", json!({}), &socket_ctx())
        .unwrap_err();
    assert_eq!(unknown.code, ErrorCode::InvalidArgument);
    let _ = me();
}

#[test]
fn watch_list_shows_the_folders_after_a_scan() {
    let svc = svc("ops-watch", |_| {});
    let (folder, watch) = drop_folder(&svc, "drop");
    std::os::unix::fs::symlink("/etc/hostname", folder.join("link.sh")).unwrap();
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    settle(&mut watcher, &env);
    svc.service.watch.publish(watcher.statuses());
    let list = call(&svc, "watch.list", json!({})).unwrap();
    let folder = &list["folders"][0];
    assert_eq!(folder["state"], "watching");
    assert_eq!(folder["refused"][0]["name"], "link.sh");
    assert!(
        folder["refused"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("symbolic link")
    );
}
