// SPDX-License-Identifier: MIT
use super::*;
use crate::disks::fixture::{Fixture, require_tools};
use std::process::Command;

fn never() -> AtomicBool {
    AtomicBool::new(false)
}

fn qemu_json(args: &[&str], image: &Path) -> serde_json::Value {
    let output = Command::new("qemu-img")
        .args(args)
        .arg("--output=json")
        .arg(image)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    serde_json::from_slice(&output.stdout).unwrap()
}

/// A raw image with 20 MiB of data in a 64 MiB file.
fn big_image(fixture: &Fixture) -> PathBuf {
    let tree = fixture.standard_tree("tree");
    let data: Vec<u8> = (0..20u32 * 1024 * 1024)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    fs::write(tree.join("home/user/data.bin"), data).unwrap();
    let image = fixture.ext4("big.ext4", &tree, &[]);
    fs::OpenOptions::new()
        .write(true)
        .open(&image)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    image
}

fn sum(path: &Path) -> String {
    super::super::dump::sha256_file(path, &never(), |_, _| {}).unwrap()
}

#[test]
fn a_sparse_raw_export_is_identical_and_stays_sparse() {
    require_tools!();
    let fixture = Fixture::new();
    let image = big_image(&fixture);
    let target = fixture.path("saved.ext4");
    let mut percents = Vec::new();
    let done = export(
        Path::new("qemu-img"),
        &image,
        &target,
        ExportFormat::SparseRaw,
        &never(),
        |percent| percents.push(percent),
    )
    .unwrap();
    assert_eq!(done.path, fs::canonicalize(&target).unwrap());
    assert_eq!(done.size, 64 * 1024 * 1024);
    assert_eq!(sum(&target), sum(&image));
    let source_allocated = fs::metadata(&image).unwrap().blocks() * 512;
    // Sparse: comparable to the source, far below the logical size.
    assert!(done.allocated < 40 * 1024 * 1024, "{}", done.allocated);
    assert!(
        done.allocated <= source_allocated + 4 * 1024 * 1024,
        "{} vs {source_allocated}",
        done.allocated
    );
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // No temporary file is left beside it.
    let names: Vec<_> = fs::read_dir(&fixture.root)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".part-"))
        .collect();
    assert!(names.is_empty(), "{names:?}");
}

use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn a_qcow2_export_is_standalone_compressed_and_round_trips() {
    require_tools!();
    let fixture = Fixture::new();
    let image = big_image(&fixture);
    let target = fixture.path("saved.qcow2");
    export(
        Path::new("qemu-img"),
        &image,
        &target,
        ExportFormat::Qcow2,
        &never(),
        |_| {},
    )
    .unwrap();
    let info = qemu_json(&["info", "-f", "qcow2"], &target);
    assert_eq!(info["format"], "qcow2");
    assert_eq!(info["virtual-size"], 64 * 1024 * 1024);
    // No backing file, so it opens anywhere.
    assert!(info.get("backing-filename").is_none(), "{info}");
    // Round trip: back to raw, identical bytes.
    let back = fixture.path("back.raw");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "qcow2", "-O", "raw"])
            .arg(&target)
            .arg(&back)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(sum(&back), sum(&image));
    assert!(
        Command::new("qemu-img")
            .args(["compare", "-f", "raw", "-F", "qcow2"])
            .arg(&image)
            .arg(&target)
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn a_cancelled_or_failed_export_leaves_nothing_and_keeps_an_existing_file() {
    require_tools!();
    let fixture = Fixture::new();
    let image = big_image(&fixture);
    let target = fixture.path("existing.ext4");
    fs::write(&target, "precious").unwrap();
    let cancelled = export(
        Path::new("qemu-img"),
        &image,
        &target,
        ExportFormat::SparseRaw,
        &AtomicBool::new(true),
        |_| {},
    );
    assert_eq!(cancelled.unwrap_err(), "cancelled");
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
    // The source is not an image: qemu-img still copies bytes, so use a
    // missing source for the failure.
    let failed = export(
        Path::new("qemu-img"),
        &fixture.path("absent.ext4"),
        &target,
        ExportFormat::Qcow2,
        &never(),
        |_| {},
    );
    assert!(failed.is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
    let leftovers: Vec<_> = fs::read_dir(&fixture.root)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().contains(".part-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn bad_destinations_are_refused() {
    require_tools!();
    let fixture = Fixture::new();
    let image = fixture.standard_image();
    let run = |destination: &Path| {
        export(
            Path::new("qemu-img"),
            &image,
            destination,
            ExportFormat::SparseRaw,
            &never(),
            |_| {},
        )
        .unwrap_err()
    };
    assert!(run(Path::new("relative.img")).contains("absolute"));
    assert!(run(&fixture.path("no-such-folder/out.img")).contains("no-such-folder"));
    assert!(run(&image).contains("the image itself"));
    // Through a hard link too.
    let link = fixture.path("hard.ext4");
    fs::hard_link(&image, &link).unwrap();
    assert!(run(&link).contains("the image itself"));
    assert!(fs::metadata(&image).unwrap().len() > 0);
}
