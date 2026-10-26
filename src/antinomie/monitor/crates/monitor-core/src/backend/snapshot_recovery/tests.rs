// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn vm() -> VmConfig {
    VmConfig {
        id: "vm-1".into(),
        ..VmConfig::default()
    }
}

fn bundle(identity: &str) -> Bundle {
    serde_json::from_value(serde_json::json!({
        "kernel": "/home/user/k",
        "base_disk": "/home/user/d",
        "initrd": null,
        "base_identity": identity,
    }))
    .unwrap()
}

fn checkpoint(change: impl FnOnce(&mut serde_json::Value)) -> HostCheckpoint {
    let mut value = serde_json::json!({
        "schema": 1,
        "source_boot_id": "boot-1",
        "boot_bundle_identity": "boot-base",
        "disk_bundle_identity": "disk-base",
        "runs": [],
        "captures": [],
    });
    change(&mut value);
    serde_json::from_value(value).unwrap()
}

fn run(id: &str, vm_id: &str, root: u64, session: u64) -> RunSummary {
    RunSummary {
        started_ms: None,
        clock_anchor: None,
        id: id.into(),
        vm_id: vm_id.into(),
        boot_id: "boot-1".into(),
        session_id: session,
        root_task_cookie: root,
        pid: 10,
        request: ExecRequest {
            core_dump_on_exit: true,
            ..ExecRequest::default()
        },
        directory: PathBuf::new(),
        terminal_eof: true,
        state: RunState::Running,
        recording_error: None,
        execution: None,
        analysis: None,
        notes: Vec::new(),
        machine: None,
        route: None,
    }
}

fn check(checkpoint: &HostCheckpoint) -> Result<(), String> {
    checkpoint.validate(&vm(), &bundle("boot-base"), &bundle("disk-base"))
}

fn with_runs(runs: Vec<RunSummary>) -> HostCheckpoint {
    let mut checkpoint = checkpoint(|_| {});
    checkpoint.runs = runs;
    checkpoint
}

#[test]
fn an_empty_checkpoint_of_this_vm_and_these_bases_is_accepted() {
    assert_eq!(check(&checkpoint(|_| {})), Ok(()));
}

#[test]
fn a_checkpoint_of_another_schema_boot_or_base_is_refused() {
    let wrong_schema = checkpoint(|value| value["schema"] = 2.into());
    let no_boot = checkpoint(|value| value["source_boot_id"] = "".into());
    let long_boot = checkpoint(|value| value["source_boot_id"] = "b".repeat(129).into());
    let other_boot_base = checkpoint(|value| value["boot_bundle_identity"] = "other".into());
    let other_disk_base =
        checkpoint(|value| value["disk_bundle_identity"] = serde_json::Value::Null);
    for (name, checkpoint) in [
        ("schema", wrong_schema),
        ("empty boot id", no_boot),
        ("long boot id", long_boot),
        ("boot base", other_boot_base),
        ("disk base", other_disk_base),
    ] {
        assert!(check(&checkpoint).is_err(), "{name}");
    }
}

#[test]
fn runs_need_this_vm_and_distinct_nonzero_identities() {
    assert_eq!(
        check(&with_runs(vec![
            run("a", "vm-1", 5, 1),
            run("b", "vm-1", 6, 2)
        ])),
        Ok(())
    );
    for (name, runs) in [
        ("another vm", vec![run("a", "vm-2", 5, 1)]),
        ("zero root", vec![run("a", "vm-1", 0, 1)]),
        ("zero session", vec![run("a", "vm-1", 5, 0)]),
        (
            "repeated root",
            vec![run("a", "vm-1", 5, 1), run("b", "vm-1", 5, 2)],
        ),
        (
            "repeated session",
            vec![run("a", "vm-1", 5, 1), run("b", "vm-1", 6, 1)],
        ),
    ] {
        assert!(check(&with_runs(runs)).is_err(), "{name}");
    }
}

#[test]
fn too_many_runs_are_refused_before_any_are_read() {
    let runs = (0..4097)
        .map(|index| run("r", "vm-1", index + 1, index + 1))
        .collect();
    assert!(check(&with_runs(runs)).is_err());
}

fn handle(run: &str, core_id: u64, root: u64) -> process_core::SavedHandle {
    process_core::SavedHandle {
        source_run_id: run.into(),
        core_id,
        max_size: 1 << 20,
        root_cookie: root,
        tgid: 10,
    }
}

#[test]
fn a_core_handle_must_name_a_run_of_this_boot_and_own_its_id_and_root() {
    let mut named = with_runs(vec![run("a", "vm-1", 5, 1)]);
    named.core_handles.push(handle("a", 1, 5));
    assert_eq!(check(&named), Ok(()));
    let mut absent = with_runs(vec![run("a", "vm-1", 5, 1)]);
    absent.core_handles.push(handle("missing", 1, 5));
    assert!(check(&absent).is_err(), "no such run");
    let mut other_boot = with_runs(vec![run("a", "vm-1", 5, 1)]);
    other_boot.runs[0].boot_id = "boot-2".into();
    other_boot.core_handles.push(handle("a", 1, 5));
    assert!(check(&other_boot).is_err(), "another recording timeline");
    let mut repeated = with_runs(vec![run("a", "vm-1", 5, 1), run("b", "vm-1", 6, 2)]);
    repeated.core_handles.push(handle("a", 1, 5));
    repeated.core_handles.push(handle("b", 1, 6));
    assert!(check(&repeated).is_err(), "one core id twice");
}
