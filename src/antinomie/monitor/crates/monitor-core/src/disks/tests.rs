// SPDX-License-Identifier: GPL-3.0-only
use super::{
    fixture::{Fixture, require_tools},
    *,
};
use serde_json::json;

#[test]
fn sizes_read_in_binary_units() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(1023), "1023 B");
    assert_eq!(format_size(1024), "1.0 KiB");
    assert_eq!(format_size(812 * 1024 * 1024), "812 MiB");
    assert_eq!(format_size(2_040_109_466), "1.9 GiB");
    assert_eq!(format_size(16 * 1024 * 1024 * 1024), "16.0 GiB");
    assert_eq!(format_size(u64::MAX), "16384 PiB");
}

#[test]
fn the_superblock_state_tells_clean_from_forced_off() {
    require_tools!();
    let fixture = Fixture::new();
    let tree = fixture.standard_tree("tree");
    let clean = fixture.ext4("clean.ext4", &tree, &[]);
    assert_eq!(read_state(&clean).unwrap(), Ext4State::Clean);
    let forced = fixture.ext4("forced.ext4", &tree, &["ssv state 0"]);
    assert_eq!(read_state(&forced).unwrap(), Ext4State::NotClean);
    assert_eq!(Ext4State::Clean.label(), "clean");
    assert_eq!(Ext4State::NotClean.label(), "not cleanly unmounted");

    for (name, data) in [
        ("empty", Vec::new()),
        ("zeros", vec![0u8; 4096]),
        ("short", vec![0xEF; 1000]),
    ] {
        let path = fixture.path(name);
        fs::write(&path, data).unwrap();
        assert!(read_state(&path).is_err(), "{name}");
    }
    assert!(read_state(&fixture.path("absent")).is_err());
}

#[test]
fn map_listings_sum_their_data_extents() {
    let extents = vec![
        json!({"start": 0, "length": 65536, "depth": 1, "present": true, "zero": false, "data": true}),
        json!({"start": 65536, "length": 131072, "depth": 0, "present": true, "zero": true, "data": false}),
        json!({"start": 196608, "length": 4096, "depth": 0, "present": true, "zero": true, "data": true}),
        json!({"start": 200704, "length": 8192, "depth": 0, "present": false, "zero": false, "data": false}),
        json!({"start": 208896, "length": 32768, "depth": 2, "present": true, "zero": false, "data": true}),
    ];
    assert_eq!(measure::map_data_size(&extents), 65536 + 32768);
    assert_eq!(measure::map_data_size(&[]), 0);
}

#[test]
fn scratch_folders_are_swept_and_nothing_else() {
    let fixture = Fixture::new();
    let disks = disks_dir(&fixture.root);
    for name in [".scratch-old", ".scratch-newer", "dump-id", "extracted"] {
        fs::create_dir_all(disks.join(name)).unwrap();
    }
    fs::write(disks.join(".scratch-old/root.ext4"), "x").unwrap();
    // A file with a scratch name is not a folder of ours.
    fs::write(disks.join(".scratch-file"), "x").unwrap();
    let keep = disks.join(".scratch-newer");
    assert_eq!(sweep_scratch(&disks, Some(&keep)), 1);
    assert!(!disks.join(".scratch-old").exists());
    assert!(keep.exists() && disks.join("dump-id").exists() && disks.join("extracted").exists());
    assert!(disks.join(".scratch-file").exists());
    assert_eq!(sweep_scratch(&disks, None), 1);
    assert_eq!(sweep_scratch(&fixture.path("missing"), None), 0);
}

#[test]
fn removing_a_view_deletes_only_a_scratch_folder() {
    let fixture = Fixture::new();
    let disks = disks_dir(&fixture.root);
    let folder = scratch_dir(&disks, "abc");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join(IMAGE_FILE), "image").unwrap();
    let view = CurrentDiskView {
        image: folder.join(IMAGE_FILE),
        ..CurrentDiskView::default()
    };
    remove_scratch(&view);
    assert!(!folder.exists());
    // An empty extraction folder goes with it; one with files stays.
    let extracted = disks.join(EXTRACTED_DIR).join("abc");
    fs::create_dir_all(&extracted).unwrap();
    let view = CurrentDiskView {
        image: scratch_dir(&disks, "abc").join(IMAGE_FILE),
        extract_dir: extracted.clone(),
        ..CurrentDiskView::default()
    };
    fs::create_dir_all(view.image.parent().unwrap()).unwrap();
    remove_scratch(&view);
    assert!(!extracted.exists() && !disks.join(EXTRACTED_DIR).exists());
    fs::create_dir_all(&extracted).unwrap();
    fs::write(extracted.join("1-passwd"), "root").unwrap();
    fs::create_dir_all(view.image.parent().unwrap()).unwrap();
    remove_scratch(&view);
    assert!(extracted.join("1-passwd").exists());
    // A view whose image is somewhere else (a future kept dump) is left alone.
    let other = disks.join("dump-1");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join(IMAGE_FILE), "image").unwrap();
    remove_scratch(&CurrentDiskView {
        image: other.join(IMAGE_FILE),
        ..CurrentDiskView::default()
    });
    assert!(other.join(IMAGE_FILE).exists());
}

#[test]
fn space_checks_name_the_folder_and_both_figures() {
    let mut measure = DiskMeasure {
        directory: PathBuf::from("/home/user/rec/disks"),
        logical_size: 16 * 1024 * 1024 * 1024,
        allocated_estimate: 2 * 1024 * 1024 * 1024,
        free_space: 1024 * 1024 * 1024,
        sparse_supported: true,
        ..DiskMeasure::default()
    };
    let error = measure.space_error().unwrap();
    assert!(error.contains("/home/user/rec/disks"), "{error}");
    assert!(
        error.contains("2.1 GiB") && error.contains("1.0 GiB"),
        "{error}"
    );
    measure.free_space = 3 * 1024 * 1024 * 1024;
    assert!(measure.space_error().is_none());
    // Without sparse files the whole logical size is needed.
    measure.sparse_supported = false;
    let error = measure.space_error().unwrap();
    assert!(
        error.contains("16.1 GiB") && error.contains("sparse"),
        "{error}"
    );
}

#[test]
fn a_measure_of_a_chain_reports_size_layers_and_estimate() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let measured = measure::measure(
        Path::new("qemu-img"),
        "vm-1",
        &fixture.root,
        &top,
        DiskSourceRecord::default(),
        &disks_dir(&fixture.root),
        None,
    );
    assert_eq!(measured.error, None);
    assert_eq!(measured.logical_size, 32 * 1024 * 1024);
    assert!(
        measured.allocated_estimate > 0 && measured.allocated_estimate <= measured.logical_size
    );
    assert!(measured.free_space > measured.allocated_estimate);
    let names: Vec<_> = measured
        .source
        .layers
        .iter()
        .map(|l| l.filename.as_str())
        .collect();
    assert_eq!(names, ["layer-2.qcow2", "layer-1.qcow2", "layer-0.qcow2"]);
    assert!(
        measured
            .source
            .layers
            .iter()
            .all(|layer| layer.size > 0 && layer.modified_ms > 0)
    );
    assert!(disks_dir(&fixture.root).is_dir());
}

#[test]
fn measuring_a_missing_chain_reports_the_error_on_the_card() {
    require_tools!();
    let fixture = Fixture::new();
    let measured = measure::measure(
        Path::new("qemu-img"),
        "vm-1",
        &fixture.root,
        &fixture.path("absent.qcow2"),
        DiskSourceRecord::default(),
        &disks_dir(&fixture.root),
        None,
    );
    assert!(measured.error.unwrap().contains("qemu-img"));
}
