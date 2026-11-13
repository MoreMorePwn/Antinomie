// SPDX-License-Identifier: GPL-3.0-only
//! Cross-surface security cases of design 7.2 T9 (card P5-2): what no single
//! surface's own tests can show, because the case runs through two or more of
//! them (the socket ops, the retry, the watch folders, the log).

use super::{
    tests::{SCRIPT, call, me, svc, svc_logged, upload},
    watch_env::ServiceEnv,
};
use crate::{
    api::{
        error::ErrorCode,
        failure::{Failure, FailureCode},
        run::{Outcome, RunState, Stage},
    },
    config::service::{DeleteAfter, Watch},
    store::{Eligibility, tests::lane},
    watch::Watcher,
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    sync::{Arc, Mutex},
};

/// A spec with one wrong member is refused with `invalid_argument` naming it,
/// at every level, in every op that takes one; nothing is queued.
#[test]
fn an_unknown_member_is_refused_by_name_in_every_op_that_takes_a_spec() {
    let svc = svc("t9-unknown", |_| {});
    let id = upload(&svc, SCRIPT);
    let sample = json!({"upload_id": id});
    let cases = [
        (json!({"sample": sample, "evil": 1}), "evil"),
        (json!({"sample": {"upload_id": id, "evil": 1}}), "evil"),
        (
            json!({"sample": sample, "overrides": {"evil": true}}),
            "overrides",
        ),
        (
            json!({"sample": sample, "overrides": {"program": {"evil": 1}}}),
            "overrides.program.evil",
        ),
        (
            json!({"sample": sample, "overrides": {"static": {"evil": 1}}}),
            "overrides.static",
        ),
        (json!({"sample": sample, "labels": {"a": 1}}), "params"),
        (json!({"sample": sample, "priority": -1}), "params"),
    ];
    for (params, field) in cases {
        let error = call(&svc, "run.submit", params.clone()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{params}");
        assert_eq!(error.field.as_deref(), Some(field), "{params}: {error:?}");
    }
    // The same on the other ops that take structured parameters.
    for (op, params) in [
        ("run.get", json!({"run_id": "j_x", "evil": 1})),
        (
            "run.rerun",
            json!({"run_id": "j_x", "overrides": {"evil": 1}}),
        ),
        ("upload.begin", json!({"size": 3, "evil": 1})),
        ("run.list", json!({"evil": 1})),
    ] {
        let error = call(&svc, op, params).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{op}");
    }
    let listed = call(&svc, "run.list", json!({})).unwrap();
    assert!(listed["runs"].as_array().unwrap().is_empty(), "{listed}");
}

fn denied_field(reply: &Value) -> Option<String> {
    (reply["state"] == "rejected").then(|| {
        reply["failure"]["detail"]
            .as_str()
            .and_then(|d| d.strip_prefix("field: "))
            .unwrap_or_default()
            .to_owned()
    })
}

/// A run cannot ask for more than the node gives, even for the owner who
/// holds every permission: not a live route (not set up on this node), not a
/// kept VM, not a run past the node ceiling, not a key 0.9.0 reserves. The
/// same through a retry's overrides, and a watched file brings no overrides
/// at all. (A preset locks nothing else: the owner may run as root or take
/// dumps.)
#[test]
fn no_override_climbs_above_the_node_through_submit_retry_or_a_watch() {
    let svc = svc("t9-escalate", |_| {});
    let id = upload(&svc, SCRIPT);
    let escalations = [
        (json!({"network": {"route": "tor"}}), "network.route"),
        (json!({"network": {"route": "internet"}}), "network.route"),
        (json!({"network": {"route": "nat"}}), "network.route"),
        (
            json!({"vm": {"keep_on_failure": true}}),
            "vm.keep_on_failure",
        ),
        (
            json!({"program": {"run_time_s": 999_999}}),
            "overrides.program.run_time_s",
        ),
        (
            json!({"program": {"run_in": "guest_desktop"}}),
            "program.run_in",
        ),
        (
            json!({"network": {"abuse_filter": false}}),
            "network.abuse_filter",
        ),
    ];
    for (overrides, field) in &escalations {
        let spec = json!({"sample": {"upload_id": id}, "overrides": overrides});
        match call(&svc, "run.submit", spec) {
            Ok(reply) => {
                assert_eq!(reply["state"], "rejected", "{overrides}: {reply}");
                assert_eq!(denied_field(&reply).as_deref(), Some(*field), "{reply}");
            }
            // A value out of range or a reserved key is refused and stores
            // nothing.
            Err(error) => {
                assert!(
                    matches!(
                        error.code,
                        ErrorCode::Unsupported | ErrorCode::InvalidArgument
                    ),
                    "{overrides}: {error:?}"
                );
                assert_eq!(error.field.as_deref(), Some(*field), "{error:?}");
            }
        }
    }

    // A finished job retried with the same escalations is refused the same way.
    let first = call(&svc, "run.submit", json!({"sample": {"upload_id": id}})).unwrap();
    let store = &svc.service.store;
    let running = store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    store
        .finish(
            &running.id,
            Outcome::Failed,
            Some(Failure::new(
                FailureCode::GuestLost,
                Stage::Run,
                "lost",
                None,
            )),
        )
        .unwrap();
    for (overrides, field) in &escalations {
        match call(
            &svc,
            "run.rerun",
            json!({"run_id": first["id"], "overrides": overrides}),
        ) {
            Ok(reply) => {
                assert_eq!(reply["state"], "rejected", "{overrides}: {reply}");
                assert_eq!(denied_field(&reply).as_deref(), Some(*field), "{reply}");
            }
            Err(error) => {
                assert!(
                    matches!(
                        error.code,
                        ErrorCode::InvalidArgument | ErrorCode::Unsupported
                    ),
                    "{overrides}: {error:?}"
                );
                assert_eq!(error.field.as_deref(), Some(*field), "{error:?}");
            }
        }
    }
    let queued = call(&svc, "run.list", json!({"state": "queued"})).unwrap();
    assert!(
        queued["runs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|job| job["request"]["overrides"]["network"].is_null()
                && job["request"]["overrides"]["vm"].is_null()),
        "{queued}"
    );
}

fn drop_folder(svc: &super::tests::Svc, name: &str) -> (std::path::PathBuf, Watch) {
    let folder = svc.dir.join(name);
    fs::create_dir_all(&folder).unwrap();
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
    let watch = Watch {
        path: folder.clone(),
        preset: "standard".into(),
        recursive: false,
        delete_after: DeleteAfter::Move,
        on_duplicate: None,
        preset_by_dir: false,
        allow_group_write: false,
        watch_rate: 50,
        permissions: Vec::new(),
        priority_max: None,
        policy: None,
        policy_by_dir: None,
    };
    (folder, watch)
}

fn scan(svc: &super::tests::Svc, watch: Watch) {
    let env = ServiceEnv(svc.service.clone());
    let mut watcher = Watcher::new(&svc.dir.join("data").join("inbox"));
    watcher.configure(&[watch]);
    for t in [0, 2_000, 4_000, 6_000] {
        watcher.scan_all(&env, t);
    }
}

/// Names an attacker chooses reach the job, the library and the folders
/// `processed/` and `rejected/` as data: nothing is created outside, the names
/// kept on disk are plain, and a job carries the name as text only.
#[test]
fn hostile_file_names_in_a_watch_folder_stay_data_from_the_folder_to_the_job() {
    let svc = svc("t9-hostile-names", |_| {});
    let (folder, watch) = drop_folder(&svc, "drop");
    let mut names: Vec<OsString> = vec![
        "a\nb.sh".into(),
        "esc\x1b]0;pwn\x07.sh".into(),
        "$(touch pwned).sh".into(),
        "`id`;rm -rf x.sh".into(),
        "quote\"'.sh".into(),
        "<script>alert(1)<b>.sh".into(),
        "-rf.sh".into(),
        "..sh".into(),
        format!("{}.sh", "n".repeat(200)).into(),
        OsString::from_vec(b"bad-\xff\xfe-utf8.sh".to_vec()),
    ];
    names.sort();
    for (n, name) in names.iter().enumerate() {
        // Each file differs so that none is a duplicate of another.
        let mut bytes = SCRIPT.to_vec();
        bytes.extend_from_slice(format!("# {n}\n").as_bytes());
        fs::write(folder.join(name), bytes).unwrap();
    }
    scan(&svc, watch);

    let inbox = svc.dir.join("data").join("inbox");
    for sub in ["processed", "rejected"] {
        for entry in fs::read_dir(inbox.join(sub))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && !name.starts_with('.'),
                "{sub}/{name:?}"
            );
        }
    }
    assert!(!svc.dir.join("pwned").exists());
    assert!(!folder.join("pwned").exists());
    assert!(!inbox.join("pwned").exists());
    let listed = call(&svc, "run.list", json!({})).unwrap();
    let jobs = listed["runs"].as_array().unwrap();
    assert_eq!(
        jobs.len() + count(&folder),
        names.len(),
        "every name is either a job or still where it was left"
    );
    // Only the names that cannot become a stored name stay behind.
    for left in fs::read_dir(&folder).unwrap().flatten() {
        let left = left.file_name().to_string_lossy().into_owned();
        assert!(
            left.starts_with('.') || left.len() > 100 || left.contains(['"', '\'']),
            "{left:?}"
        );
    }
    for job in jobs {
        let name = job["sample"]["name"].as_str().unwrap();
        assert!(name.len() <= 128, "{name:?}");
        assert!(!name.contains(['/', '\0']), "{name:?}");
        // The name is data only: it is in no argument or environment entry.
        let overrides = &job["request"]["overrides"];
        assert!(overrides["args"].is_null() && overrides["env"].is_null());
    }
}

fn count(dir: &std::path::Path) -> usize {
    fs::read_dir(dir).map(|rd| rd.count()).unwrap_or(0)
}

/// A link or a hard link to a file outside the folder is never read through
/// the watch, and the outside file keeps its content, mode and link count.
#[test]
fn a_link_or_hard_link_in_a_watch_folder_never_reaches_the_library() {
    let svc = svc("t9-links", |_| {});
    let (folder, watch) = drop_folder(&svc, "drop");
    let outside = svc.dir.join("secret.sh");
    fs::write(&outside, SCRIPT).unwrap();
    std::os::unix::fs::symlink(&outside, folder.join("soft.sh")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", folder.join("etc.sh")).unwrap();
    fs::hard_link(&outside, folder.join("hard.sh")).unwrap();
    scan(&svc, watch);

    let listed = call(&svc, "run.list", json!({})).unwrap();
    assert!(listed["runs"].as_array().unwrap().is_empty(), "{listed}");
    let library = antinomie_monitor_core::samples::Library::open(&svc.dir.join("data")).unwrap();
    assert!(library.list().unwrap().is_empty());
    // Refused entries stay where they are; nothing was moved or deleted.
    for name in ["soft.sh", "etc.sh", "hard.sh"] {
        assert!(folder.join(name).symlink_metadata().is_ok(), "{name}");
    }
    assert_eq!(fs::read(&outside).unwrap(), SCRIPT);
    use std::os::unix::fs::MetadataExt;
    assert_eq!(fs::metadata(&outside).unwrap().nlink(), 2);
}

/// The log of the service is one line per entry and carries no control
/// character a hostile name, label or error text could smuggle in.
#[test]
fn hostile_text_in_a_spec_never_breaks_the_service_log() {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let svc = svc_logged(
        "t9-log",
        |_| {},
        Arc::new(move |line: &str| sink.lock().unwrap().push(line.to_owned())),
    );
    let id = upload(&svc, SCRIPT);
    let hostile = "evil\n[ERROR] forged\x1b[31m<script>alert(1)</script>";
    for params in [
        json!({"sample": {"upload_id": id}, "name": hostile, "labels": {"k": hostile}}),
        json!({"sample": {"upload_id": id}, "idempotency_key": hostile}),
        json!({"sample": {"path": hostile}}),
        json!({"sample": {"sha256": hostile}}),
        json!({hostile: 1}),
    ] {
        let _ = call(&svc, "run.submit", params);
    }
    let _ = call(&svc, "run.get", json!({"run_id": hostile}));
    let _ = call(&svc, hostile, json!({}));
    let job = call(&svc, "run.list", json!({})).unwrap();
    // Whatever was accepted is returned as JSON text, escaped by the encoder.
    let wire = serde_json::to_string(&job).unwrap();
    assert!(!wire.contains('\n') && !wire.contains('\x1b'), "{wire}");
    for line in lines.lock().unwrap().iter() {
        assert!(
            !line.trim_end_matches('\n').contains(['\n', '\x1b', '\r']),
            "{line:?}"
        );
    }
    assert_eq!(me().client_id, me().client_id);
    let _ = RunState::Queued;
}
