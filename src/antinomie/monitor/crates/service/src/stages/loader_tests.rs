// SPDX-License-Identifier: GPL-3.0-only
//! The sample's loader against the lane's base (`loader`, ANT-T0556 A51 and
//! E13): the pure checks, and `prechecks` refusing a program whose loader the
//! base lacks before the VM starts.
use super::{
    StageStop,
    loader::{base_interpreters, missing_loader},
    tests::W,
};
use crate::api::{failure::FailureCode, ids::Sha256Hex};
use antinomie_monitor_core::{
    BaseSummary, GuestArch,
    samples::{Library, NewSample},
};
use std::path::{Path, PathBuf};

/// An x86-64 ELF executable whose PT_INTERP names `interpreter` (`None`:
/// static), with one loadable segment over the whole file.
fn program(interpreter: Option<&str>) -> Vec<u8> {
    let mut file = vec![0u8; 0x200];
    file[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
    let put16 =
        |f: &mut Vec<u8>, at: usize, v: u16| f[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |f: &mut Vec<u8>, at: usize, v: u32| f[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |f: &mut Vec<u8>, at: usize, v: u64| f[at..at + 8].copy_from_slice(&v.to_le_bytes());
    put16(&mut file, 0x10, 2); // ET_EXEC
    put16(&mut file, 0x12, 62); // x86-64
    put32(&mut file, 0x14, 1);
    put64(&mut file, 0x18, 0x400100); // entry
    put64(&mut file, 0x20, 0x40); // phoff
    put16(&mut file, 0x34, 0x40);
    put16(&mut file, 0x36, 56);
    put16(&mut file, 0x38, if interpreter.is_some() { 2 } else { 1 });
    // PT_LOAD over the file.
    put32(&mut file, 0x40, 1);
    put32(&mut file, 0x44, 5);
    put64(&mut file, 0x50, 0x400000);
    put64(&mut file, 0x58, 0x400000);
    put64(&mut file, 0x60, 0x200);
    put64(&mut file, 0x68, 0x200);
    if let Some(path) = interpreter {
        let at = 0x100;
        file[at..at + path.len()].copy_from_slice(path.as_bytes());
        put32(&mut file, 0x78, 3); // PT_INTERP
        put32(&mut file, 0x7c, 4);
        put64(&mut file, 0x80, at as u64);
        put64(&mut file, 0x98, path.len() as u64 + 1);
        put64(&mut file, 0xa0, path.len() as u64 + 1);
    }
    file
}

fn glibc_base() -> Vec<String> {
    vec![
        "/lib64/ld-linux-x86-64.so.2".into(),
        "/lib/ld-linux-x86-64.so.2".into(),
    ]
}

#[test]
fn a_loader_the_base_has_or_a_static_program_is_not_refused() {
    let base = glibc_base();
    assert_eq!(
        missing_loader(&program(Some("/lib64/ld-linux-x86-64.so.2")), &base),
        None
    );
    assert_eq!(missing_loader(&program(None), &base), None);
    assert_eq!(missing_loader(b"#!/bin/sh\necho hi\n", &base), None);
}

#[test]
fn a_loader_the_base_lacks_is_named_with_its_c_library() {
    // The arm64 eval's Tsunami sample needed uClibc's (ANT-T0554 E13).
    let missing = missing_loader(&program(Some("/lib/ld-uClibc.so.0")), &glibc_base()).unwrap();
    assert_eq!(missing.interpreter, "/lib/ld-uClibc.so.0");
    let why = missing.why;
    assert!(
        why.contains("/lib/ld-uClibc.so.0 (uClibc's dynamic loader)"),
        "{why}"
    );
    assert!(why.contains("it has /lib64/ld-linux-x86-64.so.2"), "{why}");
    let bionic = missing_loader(&program(Some("/system/bin/linker64")), &glibc_base())
        .unwrap()
        .why;
    assert!(bionic.contains("Android's bionic"), "{bionic}");
    // A base built before glibc's runtime lists nothing: an empty list
    // refuses every dynamically linked program, as the guest would.
    let none = missing_loader(&program(Some("/lib64/ld-linux-x86-64.so.2")), &[])
        .unwrap()
        .why;
    assert!(none.contains("(glibc's dynamic loader)"), "{none}");
}

#[test]
fn the_list_is_read_from_the_bases_bundle() {
    let dir = std::env::temp_dir().join(format!("ant-loader-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = dir.join("bundle.json");
    assert_eq!(base_interpreters(&dir), None);
    std::fs::write(&bundle, r#"{"format": 1}"#).unwrap();
    assert_eq!(base_interpreters(&dir), None);
    std::fs::write(
        &bundle,
        r#"{"format": 1, "program_interpreters": ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-x86-64.so.2"]}"#,
    )
    .unwrap();
    assert_eq!(base_interpreters(&dir), Some(glibc_base()));
    std::fs::write(&bundle, r#"{"program_interpreters": [7]}"#).unwrap();
    assert_eq!(base_interpreters(&dir), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-loader-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn lane_base(directory: &Path) -> BaseSummary {
    BaseSummary {
        id: "busybox-r21".into(),
        label: "BusyBox".into(),
        directory: directory.to_path_buf(),
        guest: None,
        min_ram_mib: 128,
        min_disk_gib: 1,
        fixed_display: false,
        arch: GuestArch::X86_64,
        size_bytes: 1 << 20,
        revision: Some(22),
        min_app_version: None,
        built_with: None,
        stealth_support: Vec::new(),
    }
}

/// `prechecks` of a running job whose sample is `program`, on a lane whose
/// base (`busybox-r21`, the lane file's) has `bundle` as its bundle.json.
fn prechecks(name: &str, program: &[u8], bundle: &str) -> Result<(), StageStop> {
    let w = W::new(name);
    let data = scratch(&format!("{name}-data"));
    let base = scratch(&format!("{name}-base"));
    std::fs::write(base.join("bundle.json"), bundle).unwrap();
    let added = Library::open(&data)
        .unwrap()
        .add_bytes(program, NewSample::default())
        .unwrap();
    let mut job = w.fx.running(1);
    let sample = job.sample.as_mut().unwrap();
    sample.sha256 = Sha256Hex::try_from(added.sha256.clone()).unwrap();
    sample.kind = "elf".into();
    let summary = lane_base(&base);
    let mut waiter = w.engine(move |fake| {
        fake.start_with(move |s| s.bases = vec![summary]);
    });
    let mut stages = w.stages(&mut waiter);
    stages.env.data_dir = &data;
    let result = stages.prechecks(&job).map(|_| ());
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&base);
    result
}

const GLIBC_BUNDLE: &str = r#"{"format": 1, "program_interpreters": ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-x86-64.so.2"]}"#;

#[test]
fn prechecks_refuse_a_program_whose_loader_the_lanes_base_lacks() {
    let stop = prechecks(
        "uclibc",
        &program(Some("/lib/ld-uClibc.so.0")),
        GLIBC_BUNDLE,
    )
    .unwrap_err();
    let StageStop::Failed(failure) = stop else {
        panic!("not a failure: {stop:?}");
    };
    assert_eq!(failure.code, FailureCode::UnavailableOnNode);
    assert_eq!(
        failure.details.get("what").and_then(|v| v.as_str()),
        Some("program_interpreter./lib/ld-uClibc.so.0")
    );
    let detail = failure.detail.unwrap_or_default();
    assert!(detail.contains("uClibc's dynamic loader"), "{detail}");
}

#[test]
fn prechecks_pass_a_loader_the_base_has_and_a_base_without_the_list() {
    let glibc = program(Some("/lib64/ld-linux-x86-64.so.2"));
    assert!(prechecks("glibc", &glibc, GLIBC_BUNDLE).is_ok());
    assert!(prechecks("static", &program(None), GLIBC_BUNDLE).is_ok());
    // An older base: the guest reports a missing loader at launch instead.
    let uclibc = program(Some("/lib/ld-uClibc.so.0"));
    assert!(prechecks("old-base", &uclibc, r#"{"format": 1}"#).is_ok());
}
