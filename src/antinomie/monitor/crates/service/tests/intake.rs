// SPDX-License-Identifier: GPL-3.0-only
//! Uploads and intake (card P3-2b, design 4.2, 5.3 `upload.*`), with the T9
//! cases of the surface: hostile names, oversized uploads, links and special
//! files.

// `ApiError` is the contract's error type (large by design, see the crate root).
#![allow(clippy::result_large_err)]

use antinomie_monitor_core::samples::{CustodyEvent, Library, OriginKind};
use antinomie_service::{
    api::{
        error::ErrorCode,
        failure::FailureCode,
        ids::{Sha256Hex, UploadId},
        job::JobState,
        ops::{Caller, Scope, UploadBeginParams},
        spec::{JobSpec, SampleSource},
    },
    clock::ManualClock,
    config::{LoadedPolicy, Policy, PolicySet},
    intake::{
        Intake, display_name, size_limit,
        staging::{MAX_CHUNK, MAX_OPEN_PER_CLIENT, StagingStore, UPLOAD_TTL_MS},
    },
    store::{SampleAdmission, Store, SubmitLimits},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::Arc,
};

const T0: u64 = 1_794_000_000_000;
const ME: &str = "local:1000";

fn root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-intake-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fx {
    dir: PathBuf,
    data: PathBuf,
    clock: Arc<ManualClock>,
    staging: Arc<StagingStore>,
}

impl Fx {
    fn new(name: &str) -> Self {
        let dir = root(name);
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        let clock = Arc::new(ManualClock::new(T0));
        let (staging, _) =
            StagingStore::open(&data.join("inbox"), &data, clock.clone(), 256 << 20).unwrap();
        Self {
            dir,
            data,
            clock,
            staging: Arc::new(staging),
        }
    }

    fn intake(&self) -> Intake {
        Intake::new(&self.data, self.staging.clone(), None)
    }

    /// Upload `bytes` the way a client does, in chunks, and seal it.
    fn upload(&self, client: &str, name: Option<&str>, bytes: &[u8]) -> UploadId {
        let begun = self
            .staging
            .begin(
                client,
                &UploadBeginParams {
                    size: bytes.len() as u64,
                    name: name.map(str::to_owned),
                    sha256: None,
                },
            )
            .unwrap();
        let mut offset = 0u64;
        for chunk in bytes.chunks(64 * 1024) {
            let got = self
                .staging
                .put(client, &begun.upload_id, offset, chunk)
                .unwrap();
            offset = got.received;
        }
        self.staging.finish(client, &begun.upload_id).unwrap();
        begun.upload_id
    }
}

fn policy(edit: impl FnOnce(&mut Policy)) -> LoadedPolicy {
    let mut policy = Policy::default();
    policy.vm.lane_vm = Some("auto-1".into());
    edit(&mut policy);
    LoadedPolicy {
        name: "default".into(),
        digest: "d".repeat(64),
        policy,
    }
}

/// A 64-byte ELF header for `machine` (0x3e is x86-64, 0xb7 AArch64).
fn elf(machine: u16, extra: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; 64 + extra];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes
}

fn sha_of(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn source_upload(id: &UploadId) -> SampleSource {
    SampleSource {
        upload_id: Some(id.clone()),
        ..Default::default()
    }
}

fn source_path(path: &Path) -> SampleSource {
    SampleSource {
        path: Some(path.display().to_string()),
        ..Default::default()
    }
}

fn denied(
    result: Result<impl std::fmt::Debug, antinomie_service::store::IntakeError>,
) -> FailureCode {
    result.unwrap_err().code
}

// ---- the staging store ------------------------------------------------------

#[test]
fn an_upload_is_staged_hashed_and_sealed() {
    let fx = Fx::new("staging");
    let bytes = elf(0x3e, 200_000);
    let begun = fx
        .staging
        .begin(
            ME,
            &UploadBeginParams {
                size: bytes.len() as u64,
                name: Some("a.bin".into()),
                sha256: Some(Sha256Hex::try_from(sha_of(&bytes)).unwrap()),
            },
        )
        .unwrap();
    assert_eq!(begun.max_chunk, MAX_CHUNK);
    let dir = fx.data.join("inbox/uploads").join(begun.upload_id.as_str());
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(dir.join("data")).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut offset = 0;
    for chunk in bytes.chunks(70_000) {
        offset = fx
            .staging
            .put(ME, &begun.upload_id, offset, chunk)
            .unwrap()
            .received;
    }
    assert_eq!(offset, bytes.len() as u64);
    let done = fx.staging.finish(ME, &begun.upload_id).unwrap();
    assert_eq!(done.sha256.as_str(), sha_of(&bytes));
    assert_eq!(done.size, bytes.len() as u64);
    assert_eq!(done.expires_ms, T0 + UPLOAD_TTL_MS);
    // Sealed: read-only, and the answer is stable.
    assert_eq!(
        fs::metadata(dir.join("data")).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert_eq!(fx.staging.finish(ME, &begun.upload_id).unwrap(), done);
    assert_eq!(
        fx.staging
            .put(ME, &begun.upload_id, offset, b"x")
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

#[test]
fn uploads_are_strictly_sequential_and_bounded() {
    let fx = Fx::new("sequence");
    let begun = fx
        .staging
        .begin(
            ME,
            &UploadBeginParams {
                size: 10,
                name: None,
                sha256: None,
            },
        )
        .unwrap();
    let id = &begun.upload_id;
    assert_eq!(fx.staging.put(ME, id, 0, b"01234").unwrap().received, 5);
    // The wrong offset: conflict, and it says how much was received.
    let error = fx.staging.put(ME, id, 0, b"x").unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.details["received"], 5);
    assert_eq!(
        fx.staging.put(ME, id, 9, b"x").unwrap_err().code,
        ErrorCode::Conflict
    );
    // More than declared.
    assert_eq!(
        fx.staging.put(ME, id, 5, b"56789X").unwrap_err().code,
        ErrorCode::PayloadTooLarge
    );
    // A chunk above the chunk limit.
    let big = fx
        .staging
        .begin(
            ME,
            &UploadBeginParams {
                size: 3 << 20,
                name: None,
                sha256: None,
            },
        )
        .unwrap();
    let error = fx
        .staging
        .put(ME, &big.upload_id, 0, &vec![0; MAX_CHUNK as usize + 1])
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    // Incomplete: finish is refused, nothing sealed.
    assert_eq!(
        fx.staging.finish(ME, id).unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(fx.staging.put(ME, id, 5, b"56789").unwrap().received, 10);
    fx.staging.finish(ME, id).unwrap();
}

#[test]
fn begin_refuses_hostile_and_oversized_requests() {
    let fx = Fx::new("begin");
    let begin = |size: u64, name: Option<&str>| {
        fx.staging.begin(
            ME,
            &UploadBeginParams {
                size,
                name: name.map(str::to_owned),
                sha256: None,
            },
        )
    };
    assert_eq!(begin(0, None).unwrap_err().field.as_deref(), Some("size"));
    assert_eq!(
        begin((256 << 20) + 1, None).unwrap_err().code,
        ErrorCode::PayloadTooLarge
    );
    for bad in [
        "",
        "a/b",
        "../etc/passwd",
        "nul\0byte",
        "esc\u{1b}[31m",
        "new\nline",
        &"x".repeat(129),
    ] {
        let error = begin(10, Some(bad)).unwrap_err();
        assert_eq!(
            (error.code, error.field.as_deref()),
            (ErrorCode::InvalidArgument, Some("name")),
            "{bad:?}"
        );
    }
    assert!(begin(10, Some("fine name.bin")).is_ok());
    assert!(begin(10, Some(&"x".repeat(128))).is_ok());
    // Nothing the hostile requests did reached the disk outside uploads/.
    let uploads: Vec<_> = fs::read_dir(fx.data.join("inbox/uploads"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(uploads.len(), 2);
    assert!(!fx.data.join("inbox").join("etc").exists());
    // The number of open uploads per client is capped.
    for _ in 0..MAX_OPEN_PER_CLIENT - 2 {
        begin(10, None).unwrap();
    }
    assert_eq!(begin(10, None).unwrap_err().code, ErrorCode::QuotaExceeded);
    assert!(
        fx.staging
            .begin(
                "local:2000",
                &UploadBeginParams {
                    size: 10,
                    name: None,
                    sha256: None
                }
            )
            .is_ok()
    );
}

#[test]
fn a_declared_hash_must_match_and_an_upload_belongs_to_its_client() {
    let fx = Fx::new("owner");
    let begun = fx
        .staging
        .begin(
            ME,
            &UploadBeginParams {
                size: 4,
                name: None,
                sha256: Some(Sha256Hex::try_from("0".repeat(64)).unwrap()),
            },
        )
        .unwrap();
    fx.staging.put(ME, &begun.upload_id, 0, b"data").unwrap();
    assert_eq!(
        fx.staging
            .put("local:2000", &begun.upload_id, 4, b"x")
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        fx.staging
            .finish("local:2000", &begun.upload_id)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    let error = fx.staging.finish(ME, &begun.upload_id).unwrap_err();
    assert_eq!(
        (error.code, error.field.as_deref()),
        (ErrorCode::InvalidArgument, Some("sha256"))
    );
    // The failed finish sealed nothing.
    assert_eq!(
        fx.staging.sealed(ME, &begun.upload_id).unwrap_err().code,
        ErrorCode::PreconditionFailed
    );
    assert_eq!(
        fx.staging
            .finish(ME, &UploadId::from_parts(1, [0; 10]))
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
}

#[test]
fn uploads_expire_after_24_hours() {
    let fx = Fx::new("expiry");
    let open = fx
        .staging
        .begin(
            ME,
            &UploadBeginParams {
                size: 4,
                name: None,
                sha256: None,
            },
        )
        .unwrap()
        .upload_id;
    let sealed = fx.upload(ME, None, b"data");
    fx.clock.advance(UPLOAD_TTL_MS - 1);
    assert!(fx.staging.sealed(ME, &sealed).is_ok());
    assert_eq!(fx.staging.expire(), 0);
    fx.clock.advance(1);
    assert_eq!(
        fx.staging.sealed(ME, &sealed).unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(
        fx.staging.put(ME, &open, 0, b"d").unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(fx.staging.expire(), 2);
    assert_eq!(
        fs::read_dir(fx.data.join("inbox/uploads")).unwrap().count(),
        0
    );
}

#[test]
fn staging_refuses_a_separate_volume_that_can_execute() {
    let dir = root("mount");
    let data = dir.join("data");
    fs::create_dir_all(data.join("inbox/uploads")).unwrap();
    let uploads = data.join("inbox/uploads").canonicalize().unwrap();
    let data_c = data.canonicalize().unwrap();
    let table = |options: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:2 / {} rw - ext4 /dev/b rw\n3 2 8:3 / {} {options} - ext4 /dev/c rw\n",
            data_c.display(),
            uploads.display()
        )
    };
    let clock = Arc::new(ManualClock::new(T0));
    let open = |options: &str| {
        StagingStore::open_with_mounts(
            &data.join("inbox"),
            &data,
            clock.clone(),
            1 << 20,
            &table(options),
        )
    };
    assert!(open("rw,nosuid,noexec").is_ok());
    let error = open("rw,relatime").err().unwrap();
    assert!(error.contains("not mounted noexec"), "{error}");
}

// ---- the common intake ------------------------------------------------------

#[test]
fn a_staged_elf_becomes_a_library_sample_with_its_origin_and_actor() {
    let fx = Fx::new("admit");
    let bytes = elf(0x3e, 1000);
    let id = fx.upload("auto:policy-default", Some("evil.bin"), &bytes);
    let sample = fx
        .intake()
        .admit(
            &source_upload(&id),
            None,
            &policy(|_| {}),
            "auto:policy-default",
        )
        .unwrap();
    assert_eq!(sample.sha256.as_str(), sha_of(&bytes));
    assert_eq!(
        (sample.kind.as_str(), sample.architecture.as_deref()),
        ("elf", Some("x86_64"))
    );
    assert_eq!(
        (sample.size, sample.name.as_str()),
        (bytes.len() as u64, "evil.bin")
    );
    // The library holds the only copy: the staged one is gone.
    assert!(!fx.data.join("inbox/uploads").join(id.as_str()).exists());
    let library = Library::open(&fx.data).unwrap();
    let origins = library.origins(sample.sha256.as_str()).unwrap();
    assert_eq!(origins.len(), 1);
    assert_eq!(origins[0].kind, OriginKind::Added);
    assert_eq!(origins[0].source, "Automation");
    assert_eq!(origins[0].path, "evil.bin");
    // The custody entry says who.
    let entries = library.events(sample.sha256.as_str()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].by, "auto:policy-default");
    assert!(
        matches!(&entries[0].event, CustodyEvent::Added { origin } if origin.contains("Automation"))
    );
    assert!(library.custody_check(sample.sha256.as_str()).unwrap().ok());
    // A library sample can now be named by hash.
    let again = fx
        .intake()
        .admit(
            &SampleSource {
                sha256: Some(sample.sha256.clone()),
                ..Default::default()
            },
            None,
            &policy(|_| {}),
            ME,
        )
        .unwrap();
    assert_eq!(again, sample);
    // The same bytes again by another caller add an origin, not a sample.
    let id2 = fx.upload("web:bob", Some("copy.bin"), &bytes);
    fx.intake()
        .admit(&source_upload(&id2), None, &policy(|_| {}), "web:bob")
        .unwrap();
    let library = Library::open(&fx.data).unwrap();
    assert_eq!(library.origins(sample.sha256.as_str()).unwrap().len(), 2);
    let by: Vec<_> = library
        .events(sample.sha256.as_str())
        .unwrap()
        .into_iter()
        .map(|e| e.by)
        .collect();
    assert_eq!(by, ["auto:policy-default", "web:bob"]);
}

#[test]
fn type_and_architecture_are_checked_against_the_policy() {
    let fx = Fx::new("types");
    let default = policy(|_| {});
    let script = fx.upload(ME, None, b"#!/bin/sh\necho hi\n");
    assert_eq!(
        denied(
            fx.intake()
                .admit(&source_upload(&script), None, &default, ME)
        ),
        FailureCode::SampleTypeDenied
    );
    let arm = fx.upload(ME, None, &elf(0xb7, 100));
    assert_eq!(
        denied(fx.intake().admit(&source_upload(&arm), None, &default, ME)),
        FailureCode::SampleArchDenied
    );
    let exe = fx.upload(ME, None, b"MZ\x90\0 a windows program");
    assert_eq!(
        denied(fx.intake().admit(&source_upload(&exe), None, &default, ME)),
        FailureCode::SampleTypeDenied
    );
    let junk = fx.upload(ME, None, b"nothing in particular");
    assert_eq!(
        denied(fx.intake().admit(&source_upload(&junk), None, &default, ME)),
        FailureCode::SampleTypeDenied
    );
    // Nothing was added to the library by a denied sample.
    assert!(Library::open(&fx.data).unwrap().list().unwrap().is_empty());
    // A denied upload stays staged (the caller may delete it or let it expire).
    assert!(fx.staging.sealed(ME, &script).is_ok());

    // Policies that accept more.
    let loose = policy(|p| {
        p.sample.accept_types = vec!["elf".into(), "sh".into()];
        p.sample.accept_arch = vec!["x86_64".into(), "AArch64".into()];
    });
    // A script has no architecture, so accept_arch does not apply to it.
    let sample = fx
        .intake()
        .admit(&source_upload(&script), None, &loose, ME)
        .unwrap();
    assert_eq!((sample.kind.as_str(), sample.architecture), ("sh", None));
    assert!(
        fx.intake()
            .admit(&source_upload(&arm), None, &loose, ME)
            .is_ok()
    );
    let any = policy(|p| {
        p.sample.accept_types = vec!["any".into()];
        p.sample.accept_arch = vec!["any".into()];
    });
    assert!(
        fx.intake()
            .admit(&source_upload(&junk), None, &any, ME)
            .is_ok()
    );
}

#[test]
fn the_size_limit_is_the_minimum_of_three_bounds() {
    use antinomie_monitor_core::specimen_ram_bound;
    assert_eq!(size_limit(64, None), 64 << 20);
    assert_eq!(size_limit(256, None), 256 << 20);
    assert_eq!(specimen_ram_bound(2048), 512 << 20);
    assert_eq!(size_limit(256, Some(2048)), 256 << 20); // MAX_SAMPLE wins over 512 MiB
    assert_eq!(size_limit(64, Some(128)), 32 << 20); // a quarter of 128 MiB
    assert_eq!(size_limit(8, Some(128)), 8 << 20);

    let fx = Fx::new("limit");
    let two_mib = fx.upload(ME, None, &elf(0x3e, 2 << 20));
    let one_mib = policy(|p| p.sample.max_sample_mib = 1);
    assert_eq!(
        denied(
            fx.intake()
                .admit(&source_upload(&two_mib), None, &one_mib, ME)
        ),
        FailureCode::SampleTooLarge
    );
    // The VM RAM bound: 4 MiB of RAM allows 1 MiB.
    let small_vm = Intake::new(&fx.data, fx.staging.clone(), Some(4));
    assert_eq!(small_vm.max_sample_bytes(&policy(|_| {})), 1 << 20);
    assert_eq!(
        denied(small_vm.admit(&source_upload(&two_mib), None, &policy(|_| {}), ME)),
        FailureCode::SampleTooLarge
    );
    assert!(
        fx.intake()
            .admit(&source_upload(&two_mib), None, &policy(|_| {}), ME)
            .is_ok()
    );
    // A library sample is checked by its recorded size too.
    let sha = Sha256Hex::try_from(sha_of(&elf(0x3e, 2 << 20))).unwrap();
    let by_hash = SampleSource {
        sha256: Some(sha),
        ..Default::default()
    };
    assert_eq!(
        denied(small_vm.admit(&by_hash, None, &policy(|_| {}), ME)),
        FailureCode::SampleTooLarge
    );
}

#[test]
fn a_sample_that_is_not_there_is_missing() {
    let fx = Fx::new("missing");
    let default = policy(|_| {});
    let unknown = SampleSource {
        sha256: Some(Sha256Hex::try_from("ab".repeat(32)).unwrap()),
        ..Default::default()
    };
    assert_eq!(
        denied(fx.intake().admit(&unknown, None, &default, ME)),
        FailureCode::SampleMissing
    );
    let id = UploadId::from_parts(1, [3; 10]);
    assert_eq!(
        denied(fx.intake().admit(&source_upload(&id), None, &default, ME)),
        FailureCode::SampleMissing
    );
    // An upload that is not sealed yet.
    let open = fx
        .staging
        .begin(
            ME,
            &UploadBeginParams {
                size: 4,
                name: None,
                sha256: None,
            },
        )
        .unwrap()
        .upload_id;
    assert_eq!(
        denied(fx.intake().admit(&source_upload(&open), None, &default, ME)),
        FailureCode::SampleMissing
    );
    // Another client's upload.
    let theirs = fx.upload("local:2000", None, &elf(0x3e, 0));
    assert_eq!(
        denied(
            fx.intake()
                .admit(&source_upload(&theirs), None, &default, ME)
        ),
        FailureCode::SampleMissing
    );
    assert_eq!(
        denied(
            fx.intake()
                .admit(&SampleSource::default(), None, &default, ME)
        ),
        FailureCode::SampleMissing
    );
    // An expired one.
    let old = fx.upload(ME, None, &elf(0x3e, 0));
    fx.clock.advance(UPLOAD_TTL_MS);
    assert_eq!(
        denied(fx.intake().admit(&source_upload(&old), None, &default, ME)),
        FailureCode::SampleMissing
    );
}

#[test]
fn links_and_special_files_are_refused_without_blocking() {
    let fx = Fx::new("files");
    let default = policy(|_| {});
    let work = fx.dir.join("work");
    fs::create_dir_all(&work).unwrap();
    let real = work.join("real.bin");
    fs::write(&real, elf(0x3e, 10)).unwrap();
    // A symlink to a real file is not followed.
    let link = work.join("link.bin");
    symlink(&real, &link).unwrap();
    assert_eq!(
        denied(fx.intake().admit(&source_path(&link), None, &default, ME)),
        FailureCode::SampleMissing
    );
    // A directory, a FIFO (opening it for reading would block), a device.
    assert_eq!(
        denied(fx.intake().admit(&source_path(&work), None, &default, ME)),
        FailureCode::SampleMissing
    );
    let fifo = work.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
        0,
    )
    .unwrap();
    assert_eq!(
        denied(fx.intake().admit(&source_path(&fifo), None, &default, ME)),
        FailureCode::SampleMissing
    );
    assert_eq!(
        denied(
            fx.intake()
                .admit(&source_path(Path::new("/dev/null")), None, &default, ME)
        ),
        FailureCode::SampleMissing
    );
    assert_eq!(
        denied(
            fx.intake()
                .admit(&source_path(&work.join("nothing")), None, &default, ME)
        ),
        FailureCode::SampleMissing
    );
    // The regular file is fine, and only its name reaches the origin.
    let sample = fx
        .intake()
        .admit(&source_path(&real), None, &default, ME)
        .unwrap();
    let library = Library::open(&fx.data).unwrap();
    let origin = &library.origins(sample.sha256.as_str()).unwrap()[0];
    assert_eq!(origin.path, "real.bin");
    assert!(!origin.path.contains("work") && !origin.detail.contains("work"));
    // The original is not touched.
    assert!(real.exists());
}

#[test]
fn a_staged_file_swapped_for_a_link_is_not_read() {
    let fx = Fx::new("swap");
    let id = fx.upload(ME, None, &elf(0x3e, 10));
    let data = fx.data.join("inbox/uploads").join(id.as_str()).join("data");
    let secret = fx.dir.join("secret");
    fs::write(&secret, elf(0x3e, 99)).unwrap();
    fs::remove_file(&data).unwrap();
    symlink(&secret, &data).unwrap();
    assert_eq!(
        denied(
            fx.intake()
                .admit(&source_upload(&id), None, &policy(|_| {}), ME)
        ),
        FailureCode::SampleMissing
    );
    assert!(Library::open(&fx.data).unwrap().list().unwrap().is_empty());
}

#[test]
fn hostile_names_are_data_never_paths() {
    assert_eq!(
        display_name(Path::new("/srv/drop/a\u{1b}[31mb\nc")),
        "a [31mb c"
    );
    assert_eq!(display_name(Path::new("/srv/drop/ok.bin")), "ok.bin");
    assert_eq!(display_name(Path::new("/srv/drop/..")), "");
    assert_eq!(
        display_name(Path::new(&format!("/x/{}", "n".repeat(300)))).len(),
        128
    );
    // A control character in a file name does not reach the library as such.
    let fx = Fx::new("names");
    let work = fx.dir.join("work");
    fs::create_dir_all(&work).unwrap();
    let odd = work.join("bad\u{7}name.bin");
    fs::write(&odd, elf(0x3e, 5)).unwrap();
    let sample = fx
        .intake()
        .admit(&source_path(&odd), None, &policy(|_| {}), ME)
        .unwrap();
    assert!(
        !sample.name.chars().any(char::is_control),
        "{:?}",
        sample.name
    );
    let origin = &Library::open(&fx.data)
        .unwrap()
        .origins(sample.sha256.as_str())
        .unwrap()[0];
    assert!(
        !origin.path.chars().any(char::is_control) && !origin.name.chars().any(char::is_control)
    );
}

#[test]
fn submit_with_an_upload_id_queues_a_job_and_uses_up_the_upload() {
    let fx = Fx::new("submit");
    let clock = fx.clock.clone();
    let store = Store::open_with_clock(&fx.data.join("service"), clock).unwrap();
    let policies = PolicySet::single(policy(|_| {}));
    let intake = fx.intake();
    let ctx = antinomie_service::store::SubmitContext {
        policies: &policies,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let me = Caller {
        client_id: ME.into(),
        scopes: vec![Scope::Submit],
        policies: vec![],
    };
    let id = fx.upload(ME, Some("run-me"), &elf(0x3e, 64));
    let spec = JobSpec {
        sample: source_upload(&id),
        name: None,
        policy: None,
        priority: None,
        labels: Default::default(),
        idempotency_key: None,
        overrides: Default::default(),
    };
    let job = store.submit(&me, spec.clone(), &ctx).unwrap().job;
    assert_eq!(job.state, JobState::Queued);
    assert_eq!(
        job.spec.sample.sha256.as_ref(),
        Some(&job.sample.as_ref().unwrap().sha256)
    );
    assert_eq!(job.spec.sample.upload_id, None);
    assert!(!fx.data.join("inbox/uploads").join(id.as_str()).exists());
    // The upload is gone, so the same spec is a rejected job: sample_missing.
    let again = store.submit(&me, spec, &ctx).unwrap().job;
    assert_eq!(again.state, JobState::Rejected);
    assert_eq!(again.failure.unwrap().code, FailureCode::SampleMissing);
    // A type the policy denies is a rejected job with the code, and no library entry.
    let script = fx.upload(ME, None, b"#!/bin/sh\n");
    let denied_job = store
        .submit(
            &me,
            JobSpec {
                sample: source_upload(&script),
                name: None,
                policy: None,
                priority: None,
                labels: Default::default(),
                idempotency_key: None,
                overrides: Default::default(),
            },
            &ctx,
        )
        .unwrap()
        .job;
    assert_eq!(
        denied_job.failure.unwrap().code,
        FailureCode::SampleTypeDenied
    );
}
