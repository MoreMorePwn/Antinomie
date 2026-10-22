// SPDX-License-Identifier: GPL-3.0-only
//! The real `--disk-reader` worker of the `antinomie-monitor` binary, run
//! through the sandboxed `Reader` of the core crate, on a small ext4 image
//! built here with `mkfs.ext4 -d`. Skipped without bubblewrap or e2fsprogs.
use antinomie_monitor_core::disks::{
    extract,
    reader::{DiskAnswer, DiskRequest, FindMode, FindQuery, ReadError, Reader},
};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

fn tool(name: &str) -> Option<PathBuf> {
    ["/sbin", "/usr/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ant-disk-reader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn image(scratch: &Scratch) -> Option<PathBuf> {
    let mkfs = tool("mkfs.ext4")?;
    if !Path::new("/usr/bin/bwrap").is_file() || !Path::new("/usr/bin/prlimit").is_file() {
        return None;
    }
    let tree = scratch.0.join("tree");
    for directory in ["etc", "bin", "tmp"] {
        fs::create_dir_all(tree.join(directory)).unwrap();
    }
    fs::write(tree.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
    fs::write(tree.join("bin/tool"), b"\x7fELF0123456789").unwrap();
    // A link to the host's shadow file, and a name with an escape sequence.
    symlink("/etc/shadow", tree.join("etc/shadow-link")).unwrap();
    fs::write(tree.join("tmp/a\u{1b}b"), "x").unwrap();
    let raw = scratch.0.join("root.ext4");
    fs::File::create(&raw)
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    let status = Command::new(mkfs)
        .args(["-q", "-F", "-b", "4096", "-d"])
        .arg(&tree)
        .arg(&raw)
        .status()
        .unwrap();
    assert!(status.success());
    Some(raw)
}

/// The sandbox needs user namespaces; skip where the host forbids them.
fn sandbox_works(scratch: &Scratch, image: &Path) -> bool {
    let out = scratch.0.join("probe");
    let mut reader = match Reader::with_executable(
        PathBuf::from(env!("CARGO_BIN_EXE_antinomie-monitor")),
        image,
        &out,
    ) {
        Ok(reader) => reader,
        Err(_) => return false,
    };
    matches!(
        reader.request(DiskRequest::Probe),
        Ok(Ok(DiskAnswer::Probed(_)))
    )
}

#[test]
fn the_binary_serves_the_image_inside_the_sandbox_and_extracts_safely() {
    let scratch = Scratch::new();
    let Some(image) = image(&scratch) else {
        eprintln!("skipped: bubblewrap, prlimit and mkfs.ext4 are needed");
        return;
    };
    if !sandbox_works(&scratch, &image) {
        eprintln!("skipped: the sandbox cannot start here");
        return;
    }
    let out = scratch.0.join("extracted");
    let mut reader = Reader::with_executable(
        PathBuf::from(env!("CARGO_BIN_EXE_antinomie-monitor")),
        &image,
        &out,
    )
    .unwrap();
    let DiskAnswer::Listed(root) = reader
        .request(DiskRequest::List {
            path: "/".into(),
            offset: 0,
        })
        .unwrap()
        .unwrap()
    else {
        panic!("a listing")
    };
    assert!(root.entries.iter().any(|entry| entry.name == "etc"));

    // The link to /etc/shadow is a label: listed with its target, and a path
    // through it is refused. The host's file is never read.
    let DiskAnswer::Listed(etc) = reader
        .request(DiskRequest::List {
            path: "/etc".into(),
            offset: 0,
        })
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    let link = etc
        .entries
        .iter()
        .find(|entry| entry.name == "shadow-link")
        .unwrap();
    assert_eq!(link.link_target.as_deref(), Some("/etc/shadow"));
    let through = reader
        .request(DiskRequest::Info {
            path: "/etc/shadow-link/x".into(),
            hash_cap: 1 << 20,
        })
        .unwrap();
    assert!(matches!(
        through,
        Err(ReadError::Io(_) | ReadError::NotFound)
    ));

    // Extraction: the worker writes `<out>/<request id>`; the parent places
    // it under a sanitized name with mode 0600.
    let extracted = reader
        .request(DiskRequest::Extract {
            path: "/bin/tool".into(),
            max_len: 1 << 20,
        })
        .unwrap()
        .unwrap();
    assert!(matches!(extracted, DiskAnswer::Extracted(_)));
    let placed = extract::place(reader.out(), reader.last_request_id(), "/bin/tool").unwrap();
    assert_eq!(placed.file_name().unwrap(), "1-tool");
    assert_eq!(fs::read(&placed).unwrap(), b"\x7fELF0123456789");
    assert_eq!(
        fs::metadata(&placed).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // A guest path cannot name a host path.
    let hostile = reader
        .request(DiskRequest::Extract {
            path: "/etc/passwd".into(),
            max_len: 1 << 20,
        })
        .unwrap()
        .unwrap();
    assert!(matches!(hostile, DiskAnswer::Extracted(_)));
    let placed = extract::place(
        reader.out(),
        reader.last_request_id(),
        "/../../../etc/cron.d/x\u{1b}[31m",
    )
    .unwrap();
    assert!(
        placed.starts_with(fs::canonicalize(&out).unwrap()),
        "{placed:?}"
    );
    assert!(!placed
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains('\u{1b}'));

    // Find runs in the worker too.
    let DiskAnswer::Found(found) = reader
        .request(DiskRequest::Find {
            query: FindQuery {
                pattern: "tool".into(),
                mode: FindMode::Name,
            },
        })
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(found.matches.len(), 1);
}

#[test]
fn the_binary_refuses_to_run_as_a_reader_outside_the_sandbox() {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-monitor"))
        .arg("--disk-reader")
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires its sandbox"));
}

#[test]
fn an_imported_image_browses_in_the_sandbox_and_deleting_it_keeps_the_original() {
    use antinomie_monitor_core::disks::dump;
    let scratch = Scratch::new();
    let Some(image) = image(&scratch) else {
        eprintln!("skipped: bubblewrap, prlimit and mkfs.ext4 are needed");
        return;
    };
    if !sandbox_works(&scratch, &image) {
        eprintln!("skipped: the sandbox cannot start here");
        return;
    }
    // Import: a raw ext4 image only, validated before anything is recorded.
    let recordings = scratch.0.join("recordings");
    let junk = scratch.0.join("junk.img");
    fs::write(&junk, vec![0u8; 1 << 20]).unwrap();
    assert!(dump::import(&recordings, "vm", "VM", &junk).is_err());
    let truncated = scratch.0.join("truncated.ext4");
    fs::write(&truncated, &fs::read(&image).unwrap()[..4 << 20]).unwrap();
    assert!(dump::import(&recordings, "vm", "VM", &truncated)
        .unwrap_err()
        .contains("cut short"));
    assert!(dump::list(std::slice::from_ref(&recordings)).is_empty());
    let imported = dump::import(&recordings, "vm", "VM", &image).unwrap();

    // Listed and read through the sandbox like any dump: it is a plain file,
    // so it needs no running VM.
    let listed = dump::list(std::slice::from_ref(&recordings));
    assert_eq!(listed.len(), 1);
    let dump_entry = &listed[0];
    let mut reader = Reader::with_executable(
        PathBuf::from(env!("CARGO_BIN_EXE_antinomie-monitor")),
        &dump_entry.path(),
        &dump_entry.extract_dir(),
    )
    .unwrap();
    let DiskAnswer::Listed(root) = reader
        .request(DiskRequest::List {
            path: "/".into(),
            offset: 0,
        })
        .unwrap()
        .unwrap()
    else {
        panic!("a listing")
    };
    assert!(root.entries.iter().any(|entry| entry.name == "etc"));
    // Extractions of a dump live inside its own folder.
    reader
        .request(DiskRequest::Extract {
            path: "/bin/tool".into(),
            max_len: 1 << 20,
        })
        .unwrap()
        .unwrap();
    let placed = extract::place(reader.out(), reader.last_request_id(), "/bin/tool").unwrap();
    assert!(placed.starts_with(fs::canonicalize(&imported.dir).unwrap()));
    drop(reader);

    // Deleting removes the folder with the extractions, never the image.
    dump::delete(&imported).unwrap();
    assert!(!imported.dir.exists() && !placed.exists());
    assert!(image.is_file());
}
